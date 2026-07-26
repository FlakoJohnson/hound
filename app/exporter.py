"""Export the graph back to BloodHound CE v6 JSON, re-ingestible by both
Hound's own importer and BloodHound CE.

This is the inverse of importer.py, and the two must stay in step: the importer
flattens BloodHound's nested JSON into nodes + typed relationships, so exporting
means re-nesting relationships back into the fields they came from.

    Aces          <- incoming ACL edges         (r.isacl = true)
    Members       <- (member)-[:MemberOf]->(group), excluding primary-group edges
    PrimaryGroupSID <- (n)-[:MemberOf {isprimarygroup:true}]->(group)
    ChildObjects  <- (parent)-[:Contains]->(child)
    Links         <- (gpo)-[:GpLink]->(ou|domain)
    Trusts        <- (a)-[:TrustedBy]->(b), direction reconstructed from both ways
    Sessions      <- (user)-[:HasSession]->(computer)

Primary-group memberships are written back as PrimaryGroupSID rather than into
the group's Members list. Emitting both would be harmless for the graph (the
same edge either way) but would misrepresent the source data, and BloodHound
would then report an explicit membership where AD only has an implicit one.
"""

import json
import zipfile
import logging
from io import BytesIO
from collections import defaultdict

logger = logging.getLogger(__name__)

# meta.methods values mirror what SharpHound/spectral emit per file type. These
# are the exact values from a spectral collection verified to ingest cleanly into
# BloodHound CE 9.4.0 — BH does not reject other values, but matching real
# collector output keeps the archive indistinguishable from a genuine one.
_METHODS = {
    'users': 288, 'computers': 288, 'groups': 289, 'gpos': 288,
    'ous': 288, 'containers': 288, 'domains': 304,
    'certtemplates': 288, 'enterprisecas': 288, 'issuancepolicies': 288,
    'ntauthstores': 256, 'rootcas': 256, 'aiacas': 256,
}

# label -> (filename stem / meta type). Order matters only for readability.
_EXPORTS = [
    ('User', 'users'),
    ('Computer', 'computers'),
    ('Group', 'groups'),
    ('Domain', 'domains'),
    ('GPO', 'gpos'),
    ('OU', 'ous'),
    ('Container', 'containers'),
    ('CertTemplate', 'certtemplates'),
    ('EnterpriseCA', 'enterprisecas'),
    ('RootCA', 'rootcas'),
    ('AIACA', 'aiacas'),
    ('NTAuthStore', 'ntauthstores'),
    ('IssuancePolicy', 'issuancepolicies'),
]

# BloodHound only accepts these in a group's Members list. Anything else (an OU,
# a bare :Base stub) would fail ingest with an IngestibleEndpoint error, so such
# members are dropped rather than exported with a bogus type.
_MEMBER_TYPES = {'User', 'Computer', 'Group'}

# Properties that exist only inside Hound/BloodHound's own graph and are not part
# of collected data. Re-exporting them would grow on every round trip.
# hound_notes is operator commentary written by /api/notes. It must never leave
# in an export: a zip handed to a client or uploaded to a shared BloodHound
# instance would carry private engagement notes with it.
_INTERNAL_PROPS = {'system_tags', 'lastseen', 'lastcollected', 'hound_notes'}

_ACL_EXCLUDE_SUFFIX = 'Raw'

# Domain-scope predicate for a node bound as `n`. Domain nodes are matched on
# `name` too: some collectors leave `domain` unset on the domain object itself,
# which would silently drop that node and its ACEs from a scoped export while
# every other object came through. Shared by node and relationship queries so
# the two can't drift apart.
_SCOPE = '(n.domain = $domain OR (n:Domain AND n.name = $domain))'

# ACE-derived edge types, i.e. the rights that belong back in a node's Aces list.
# Identified by type rather than by an r.isacl flag: BloodHound CE's own ingest
# sets isacl, but importer.py does not (it only sets isinherited), so a graph
# populated through Hound has no isacl anywhere and keying off it exported zero
# ACEs. isacl is still honoured as a fallback for BH-sourced graphs.
_ACL_RIGHTS = {
    'GenericAll', 'GenericWrite', 'WriteOwner', 'WriteDacl', 'AllExtendedRights',
    'Owns', 'ForceChangePassword', 'AddMember', 'AddSelf',
    'ReadLAPSPassword', 'ReadGMSAPassword',
    'DCSync', 'GetChanges', 'GetChangesAll', 'GetChangesInFilteredSet',
    'WriteAccountRestrictions', 'AddKeyCredentialLink', 'WriteSPN',
    'AddAllowedToAct', 'WriteGPLink', 'SyncLAPSPassword',
    # AD CS rights
    'Enroll', 'AutoEnroll', 'ManageCA', 'ManageCertificates',
    'WritePKIEnrollmentFlag', 'WritePKINameFlag', 'DelegatedEnrollmentAgent',
}


def _node_type(labels):
    """The asserted type label, ignoring the universal :Base."""
    for lbl in labels:
        if lbl != 'Base':
            return lbl
    return 'Base'


class BloodHoundExporter:
    def __init__(self, driver):
        self.driver = driver

    def domains(self):
        """Domains present in the graph, for the export selector."""
        q = """
        MATCH (d:Domain)
        RETURN coalesce(d.name, d.objectid) AS name, d.objectid AS objectid
        ORDER BY name
        """
        with self.driver.session() as s:
            return [dict(r) for r in s.run(q)]

    # ── relationship collection ───────────────────────────────────────────────

    def _collect_edges(self, session, domain):
        """Pull every relationship the export needs in one pass per kind.

        Keyed by the object identifier of the node the field belongs to, so
        assembling a node is a dict lookup rather than a query per node.
        """
        dfilter = f'WHERE {_SCOPE}' if domain else ''
        params = {'domain': domain} if domain else {}

        aces = defaultdict(list)
        q = f"""
        MATCH (p)-[r]->(n)
        {dfilter}
        WITH p, r, n
        WHERE (type(r) IN $acl_rights OR r.isacl = true)
          AND NOT type(r) ENDS WITH '{_ACL_EXCLUDE_SUFFIX}'
        RETURN n.objectid AS target, p.objectid AS principal,
               labels(p) AS plabels, type(r) AS right,
               coalesce(r.isinherited, false) AS inherited
        """
        for rec in session.run(q, acl_rights=sorted(_ACL_RIGHTS), **params):
            if not rec['target'] or not rec['principal']:
                continue
            aces[rec['target']].append({
                'PrincipalSID': rec['principal'],
                'PrincipalType': _node_type(rec['plabels']),
                'RightName': rec['right'],
                'IsInherited': rec['inherited'],
            })

        members = defaultdict(list)
        primary = {}
        q = f"""
        MATCH (m)-[r:MemberOf]->(n:Group)
        {dfilter}
        RETURN n.objectid AS grp, m.objectid AS member, labels(m) AS mlabels,
               coalesce(r.isprimarygroup, false) AS isprimary
        """
        for rec in session.run(q, **params):
            if not rec['grp'] or not rec['member']:
                continue
            if rec['isprimary']:
                # Belongs on the member as PrimaryGroupSID, not in Members.
                primary[rec['member']] = rec['grp']
                continue
            mtype = _node_type(rec['mlabels'])
            if mtype not in _MEMBER_TYPES:
                continue
            members[rec['grp']].append({
                'ObjectIdentifier': rec['member'],
                'ObjectType': mtype,
            })

        children = defaultdict(list)
        q = f"""
        MATCH (n)-[:Contains]->(c)
        {dfilter}
        RETURN n.objectid AS parent, c.objectid AS child, labels(c) AS clabels
        """
        for rec in session.run(q, **params):
            if not rec['parent'] or not rec['child']:
                continue
            children[rec['parent']].append({
                'ObjectIdentifier': rec['child'],
                'ObjectType': _node_type(rec['clabels']),
            })

        links = defaultdict(list)
        q = f"""
        MATCH (g:GPO)-[r:GpLink]->(n)
        {dfilter}
        RETURN n.objectid AS target, g.objectid AS gpo,
               coalesce(r.isenforced, false) AS enforced
        """
        for rec in session.run(q, **params):
            if not rec['target'] or not rec['gpo']:
                continue
            links[rec['target']].append({
                'GUID': rec['gpo'],
                'IsEnforced': rec['enforced'],
            })

        sessions = defaultdict(list)
        q = f"""
        MATCH (u)-[:HasSession]->(n:Computer)
        {dfilter}
        RETURN n.objectid AS comp, u.objectid AS user
        """
        for rec in session.run(q, **params):
            if not rec['comp'] or not rec['user']:
                continue
            sessions[rec['comp']].append({
                'UserSID': rec['user'], 'ComputerSID': rec['comp'],
            })

        simple = {}
        for rel, field, reverse in [
            ('AllowedToDelegate', 'AllowedToDelegate', False),
            ('AllowedToAct', 'AllowedToAct', True),
            ('HasSIDHistory', 'HasSIDHistory', False),
            ('AdminTo', 'LocalAdmins', True),
            ('CanRDP', 'RemoteDesktopUsers', True),
            ('CanPSRemote', 'PSRemoteUsers', True),
            ('ExecuteDCOM', 'DcomUsers', True),
        ]:
            acc = defaultdict(list)
            # reverse=True means the edge points *at* the node owning the field.
            pattern = (f'MATCH (o)-[:{rel}]->(n) {dfilter} RETURN n.objectid AS owner, '
                       f'o.objectid AS other, labels(o) AS olabels') if reverse else \
                      (f'MATCH (n)-[:{rel}]->(o) {dfilter} RETURN n.objectid AS owner, '
                       f'o.objectid AS other, labels(o) AS olabels')
            for rec in session.run(pattern, **params):
                if not rec['owner'] or not rec['other']:
                    continue
                acc[rec['owner']].append({
                    'ObjectIdentifier': rec['other'],
                    'ObjectType': _node_type(rec['olabels']),
                })
            simple[field] = acc

        return {'aces': aces, 'members': members, 'primary': primary,
                'children': children, 'links': links, 'sessions': sessions,
                **simple}

    def _collect_trusts(self, session, domain):
        """Rebuild Trusts[] from TrustedBy edges.

        importer.py orients TrustedBy by direction and emits both edges for a
        bidirectional trust, so the direction is recoverable: seeing both ways
        means Bidirectional, one way means Inbound or Outbound.
        """
        q = """
        MATCH (a:Domain)-[r:TrustedBy]->(b:Domain)
        RETURN a.objectid AS src, b.objectid AS dst,
               coalesce(b.name, b.objectid) AS dst_name,
               coalesce(a.name, a.objectid) AS src_name,
               r.tt AS trust_type, coalesce(r.tr, false) AS transitive,
               coalesce(r.sf, false) AS sid_filtering
        """
        pairs = {}
        for rec in session.run(q):
            pairs[(rec['src'], rec['dst'])] = rec

        out = defaultdict(list)
        seen = set()
        for (src, dst), rec in pairs.items():
            if (src, dst) in seen:
                continue
            both = (dst, src) in pairs
            seen.add((src, dst))
            if both:
                seen.add((dst, src))
                direction = 'Bidirectional'
            else:
                direction = 'Inbound'
            if domain and rec['src_name'] != domain:
                continue
            out[src].append({
                'TargetDomainSid': dst,
                'TargetDomainName': rec['dst_name'],
                'IsTransitive': rec['transitive'],
                'TrustDirection': direction,
                'TrustType': rec['trust_type'] or 'ParentChild',
                'SidFilteringEnabled': rec['sid_filtering'],
            })
        return out

    # ── node assembly ─────────────────────────────────────────────────────────

    def _nodes(self, session, label, domain):
        if domain:
            where, params = f'WHERE {_SCOPE}', {'domain': domain}
        else:
            where, params = '', {}
        q = f"""
        MATCH (n:{label})
        {where}
        RETURN n AS node, labels(n) AS labels
        """
        for rec in session.run(q, **params):
            yield dict(rec['node']), rec['labels']

    def _build(self, label, props, edges, trusts):
        oid = props.get('objectid', '')
        clean = {k: v for k, v in props.items() if k not in _INTERNAL_PROPS}
        obj = {
            'ObjectIdentifier': oid,
            'Properties': clean,
            'Aces': edges['aces'].get(oid, []),
            'IsDeleted': bool(props.get('isdeleted', False)),
            'IsACLProtected': bool(props.get('isaclprotected', False)),
        }

        if label in ('User', 'Computer'):
            obj['PrimaryGroupSID'] = edges['primary'].get(oid) or None
            obj['AllowedToDelegate'] = edges['AllowedToDelegate'].get(oid, [])
            obj['HasSIDHistory'] = edges['HasSIDHistory'].get(oid, [])
            obj['SPNTargets'] = []

        if label == 'Computer':
            obj['AllowedToAct'] = edges['AllowedToAct'].get(oid, [])
            obj['Sessions'] = {'Collected': bool(edges['sessions'].get(oid)),
                               'FailureReason': None,
                               'Results': edges['sessions'].get(oid, [])}
            obj['PrivilegedSessions'] = {'Collected': False, 'FailureReason': None, 'Results': []}
            obj['RegistrySessions'] = {'Collected': False, 'FailureReason': None, 'Results': []}
            # Emit both the modern LocalGroups shape that BloodHound CE reads and
            # the legacy per-field lists that Hound's importer reads, so the
            # archive round-trips through either ingest path.
            local = []
            for field, rid in [('LocalAdmins', 'Administrators'),
                               ('RemoteDesktopUsers', 'Remote Desktop Users'),
                               ('PSRemoteUsers', 'Remote Management Users'),
                               ('DcomUsers', 'Distributed COM Users')]:
                results = edges[field].get(oid, [])
                obj[field] = {'Collected': bool(results), 'FailureReason': None,
                              'Results': results}
                if results:
                    local.append({'ObjectIdentifier': f'{oid}-{rid}',
                                  'Name': f'{rid.upper()}@{props.get("domain", "")}',
                                  'Collected': True, 'FailureReason': None,
                                  'Results': results, 'LocalNames': []})
            obj['LocalGroups'] = local
            obj['UserRights'] = []
            obj['DCRegistryData'] = {}
            obj['Status'] = None

        if label == 'Group':
            obj['Members'] = edges['members'].get(oid, [])

        if label in ('Domain', 'OU', 'Container'):
            obj['ChildObjects'] = edges['children'].get(oid, [])

        if label in ('Domain', 'OU'):
            obj['Links'] = edges['links'].get(oid, [])

        if label == 'Domain':
            obj['Trusts'] = trusts.get(oid, [])

        if label == 'OU':
            obj['GPOChanges'] = {'LocalAdmins': [], 'RemoteDesktopUsers': [],
                                 'DcomUsers': [], 'PSRemoteUsers': [],
                                 'AffectedComputers': []}

        return obj

    # ── entry point ───────────────────────────────────────────────────────────

    def export_zip(self, domain=None, progress_cb=None):
        """Build a BloodHound CE v6 zip in memory. Returns (bytes, stats)."""
        stats = {'files': {}, 'nodes': 0}
        buf = BytesIO()

        with self.driver.session() as session:
            edges = self._collect_edges(session, domain)
            trusts = self._collect_trusts(session, domain)

            with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
                for idx, (label, kind) in enumerate(_EXPORTS):
                    if progress_cb:
                        progress_cb(kind, idx, len(_EXPORTS))
                    data = [self._build(label, props, edges, trusts)
                            for props, _labels in self._nodes(session, label, domain)]
                    payload = {
                        'data': data,
                        'meta': {
                            'methods': _METHODS.get(kind, 0),
                            'type': kind,
                            'count': len(data),
                            'version': 6,
                        },
                    }
                    zf.writestr(f'{kind}.json',
                                json.dumps(payload, separators=(',', ':')))
                    stats['files'][kind] = len(data)
                    stats['nodes'] += len(data)

        buf.seek(0)
        return buf.getvalue(), stats
