import json
import zipfile
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

TYPE_TO_LABEL = {
    'user': 'User',
    'users': 'User',
    'computer': 'Computer',
    'computers': 'Computer',
    'group': 'Group',
    'groups': 'Group',
    'domain': 'Domain',
    'domains': 'Domain',
    'gpo': 'GPO',
    'gpos': 'GPO',
    'ou': 'OU',
    'ous': 'OU',
    'container': 'Container',
    'containers': 'Container',
    'aiaca': 'AIACA',
    'aiacas': 'AIACA',
    'rootca': 'RootCA',
    'rootcas': 'RootCA',
    'enterpriseca': 'EnterpriseCA',
    'enterprisecas': 'EnterpriseCA',
    'ntauthstore': 'NTAuthStore',
    'ntauthstores': 'NTAuthStore',
    'certtemplate': 'CertTemplate',
    'certtemplates': 'CertTemplate',
    'issuancepolicy': 'IssuancePolicy',
    'issuancepolicies': 'IssuancePolicy',
    'aztenant': 'AZTenant',
    'azuser': 'AZUser',
    'azgroup': 'AZGroup',
    'azapp': 'AZApp',
    'azserviceprincipal': 'AZServicePrincipal',
    'azvm': 'AZVM',
    'azdevice': 'AZDevice',
    'azkeyvault': 'AZKeyVault',
    'azresourcegroup': 'AZResourceGroup',
    'azsubscription': 'AZSubscription',
    'azmanagementgroup': 'AZManagementGroup',
}

# Allowlist of known BloodHound relationship types that can appear in ACE RightName fields.
# Any value from user-supplied data not in this set is rejected before Cypher interpolation.
ALLOWED_REL_TYPES = {
    # Core edges
    'MemberOf', 'HasSession', 'AdminTo', 'CanRDP', 'CanPSRemote', 'ExecuteDCOM',
    'Contains', 'GpLink', 'TrustedBy', 'AllowedToDelegate', 'AllowedToAct',
    'HasSIDHistory',
    # ACE rights
    'GenericAll', 'GenericWrite', 'WriteOwner', 'WriteDacl', 'AllExtendedRights',
    'Owns', 'ForceChangePassword', 'AddMember', 'AddSelf',
    'ReadLAPSPassword', 'ReadGMSAPassword',
    'DCSync', 'GetChanges', 'GetChangesAll', 'GetChangesInFilteredSet',
    'WriteAccountRestrictions', 'AddKeyCredentialLink', 'WriteSPN',
    # ADCS
    'Enroll', 'AutoEnroll', 'EnrollOnBehalfOf', 'OIDGroupLink',
    'IssuedSignedBy', 'NTAuthStoreFor', 'RootCAFor', 'TrustedForNTAuth', 'HostsCAService',
    'ExtendedByPolicy',
    # Azure
    'AZAddMembers', 'AZAddSecret', 'AZAvereContributor', 'AZContributor',
    'AZExecuteCommand', 'AZGetCertificates', 'AZGetKeys', 'AZGetSecrets',
    'AZGlobalAdmin', 'AZHasRole', 'AZKeyVaultContributor', 'AZLogicAppContributor',
    'AZManagedIdentity', 'AZMemberOf', 'AZNodeResourceGroup', 'AZOwns',
    'AZPrivilegedAuthAdmin', 'AZPrivilegedRoleAdmin', 'AZResetPassword', 'AZRunsAs',
    'AZSyncedToAADUser', 'AZUserAccessAdministrator', 'AZVMContributor', 'AZVMAdminLogin',
    'AZAppAdmin', 'AZCloudAppAdmin', 'AZDeviceOwner', 'AZMGAddMember',
    'AZMGAddOwner', 'AZMGAddSecret', 'AZMGGrantAppRoles', 'AZMGGrantRole',
}

# Max decompressed bytes from a single ZIP upload (2 GB)
MAX_DECOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024

# SharpHound TrustType enum → canonical name. Some collectors emit the integer
# enum, others emit the string; normalise to the string so trusttype is uniform.
_TRUST_TYPE_NAMES = {0: 'ParentChild', 1: 'CrossLink', 2: 'Forest',
                     3: 'External', 4: 'Unknown'}

# SharpHound TrustDirection enum.
_TRUST_DIR_DISABLED, _TRUST_DIR_INBOUND, _TRUST_DIR_OUTBOUND, _TRUST_DIR_BIDIR = 0, 1, 2, 3


def _norm_trust_type(v):
    """Normalise a TrustType value (int enum or string) to a canonical name."""
    if isinstance(v, bool):
        return 'Unknown'
    if isinstance(v, int):
        return _TRUST_TYPE_NAMES.get(v, str(v))
    if isinstance(v, str) and v.isdigit():
        return _TRUST_TYPE_NAMES.get(int(v), v)
    return v or 'Unknown'


def _norm_trust_dir(v):
    """Normalise a TrustDirection value (int enum or string) to an int 0-3."""
    if isinstance(v, bool):
        return _TRUST_DIR_BIDIR
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        if v.isdigit():
            return int(v)
        return {'disabled': 0, 'inbound': 1, 'outbound': 2,
                'bidirectional': 3}.get(v.lower(), _TRUST_DIR_BIDIR)
    return _TRUST_DIR_BIDIR  # default: assume bidirectional if unknown

FILE_TYPE_ORDER = ['domain', 'group', 'user', 'computer', 'gpo', 'ou', 'container',
                   'certtemplate', 'enterpriseca', 'rootca', 'aiaca', 'ntauthstore',
                   'issuancepolicy']

# AD object labels — these have a distinguishedname that encodes the domain.
# Certificate / authority labels (CertTemplate, EnterpriseCA, RootCA, AIACA,
# NTAuthStore, IssuancePolicy) have DNs rooted in the Configuration partition,
# not the domain partition, so DN-based domain inference doesn't apply.
DN_DOMAIN_LABELS = {'User', 'Computer', 'Group', 'Domain', 'GPO', 'OU', 'Container'}


def _domain_from_dn(dn):
    """Derive a domain FQDN from a distinguished name.
    'CN=Users,DC=FTBCO,DC=FTN,DC=COM' → 'FTBCO.FTN.COM'
    Returns None if the DN has no DC= components."""
    if not dn or not isinstance(dn, str):
        return None
    parts = [p.strip()[3:] for p in dn.split(',') if p.strip().upper().startswith('DC=')]
    return '.'.join(parts).upper() if parts else None


class BloodHoundImporter:
    _schema_ready = False

    def __init__(self, driver):
        self.driver = driver
        # Idempotent — actual work only runs on the first importer instance
        # per process (gated by the class-level _schema_ready flag).
        self._ensure_schema()

    def _ensure_schema(self):
        # Every node gets a :Base label so MERGE/MATCH-by-objectid resolves
        # regardless of the asserted type label. Without this, a Contains/Member
        # reference asserting ObjectType=User would create a duplicate stub
        # alongside a real Group node that already exists with the same SID
        # (cross-domain FSPs being the classic case).
        if BloodHoundImporter._schema_ready:
            return
        try:
            with self.driver.session() as session:
                session.run("CREATE CONSTRAINT base_objectid IF NOT EXISTS "
                            "FOR (n:Base) REQUIRE n.objectid IS UNIQUE")
                # Indexes on properties used in WHERE/ORDER BY across queries.
                # :Base covers all subtypes since every node carries that label.
                for idx_cypher in [
                    "CREATE INDEX base_name      IF NOT EXISTS FOR (n:Base) ON (n.name)",
                    "CREATE INDEX base_domain     IF NOT EXISTS FOR (n:Base) ON (n.domain)",
                    "CREATE INDEX base_dn         IF NOT EXISTS FOR (n:Base) ON (n.distinguishedname)",
                    "CREATE INDEX user_enabled    IF NOT EXISTS FOR (n:User) ON (n.enabled)",
                    "CREATE INDEX user_hasspn     IF NOT EXISTS FOR (n:User) ON (n.hasspn)",
                    "CREATE INDEX user_admincount IF NOT EXISTS FOR (n:User) ON (n.admincount)",
                    "CREATE INDEX user_dontreqpreauth IF NOT EXISTS FOR (n:User) ON (n.dontreqpreauth)",
                    "CREATE INDEX comp_enabled    IF NOT EXISTS FOR (n:Computer) ON (n.enabled)",
                    "CREATE INDEX comp_uncdel     IF NOT EXISTS FOR (n:Computer) ON (n.unconstraineddelegation)",
                ]:
                    session.run(idx_cypher)
            BloodHoundImporter._schema_ready = True
        except Exception as e:
            logger.warning(f"Schema setup failed: {e}")

    def _backfill_from_dn(self):
        """Three idempotent migrations that fix gaps in source data that
        carries raw LDAP attributes but not the BloodHound-canonical
        pre-processed Links / ChildObjects arrays:
          1. Set `domain` on any node that has a DN but no domain.
          2. Synthesize `Contains` edges from DN parentage (orphan tree fix).
          3. Synthesize `GpLink` edges from the raw `gplink` LDAP attribute
             on Domain / OU nodes — parses the
             [LDAP://cn={GUID},cn=policies,…;flag] segments and matches the
             GUID against each GPO's distinguishedname.
        All guards (IS NULL / NOT EXISTS / MERGE) make repeated runs no-ops."""
        try:
            with self.driver.session() as session:
                r = session.run("""
                MATCH (n)
                WHERE n.distinguishedname IS NOT NULL AND n.domain IS NULL
                WITH n, [p IN split(n.distinguishedname, ',')
                         WHERE toUpper(trim(p)) STARTS WITH 'DC='
                         | substring(trim(p), 3)] AS parts
                WHERE size(parts) > 0
                SET n.domain = toUpper(reduce(s = head(parts), p IN tail(parts) | s + '.' + p))
                RETURN count(n) AS backfilled
                """).single()
                if r and r['backfilled']:
                    logger.info(f"Backfilled domain on {r['backfilled']} node(s) from DN")

                # Link each parentless child to its DIRECT parent by computing the
                # parent DN (the child DN minus its first RDN) and matching the
                # parent by equality on distinguishedname — which hits the base_dn
                # index for an O(1) lookup per child (O(n) overall). The previous
                # ENDS WITH approach was an O(n²) cross-product that ground the DB
                # to a halt for minutes on large datasets.
                #
                # The first RDN must be split on the first UNESCAPED comma, since
                # CNs can contain escaped commas (last-name-first: CN=SMITH\, JOHN).
                # We protect '\,' with a sentinel char before splitting, then strip
                # everything up to and including the first real comma.
                r = session.run("""
                MATCH (child)
                WHERE child.distinguishedname IS NOT NULL
                  AND child.distinguishedname CONTAINS ','
                  AND NOT EXISTS { MATCH ()-[:Contains]->(child) }
                WITH child,
                     replace(child.distinguishedname, '\\\\,', '\\u0001') AS safe
                WITH child, safe,
                     substring(safe, size(split(safe, ',')[0]) + 1) AS parentSafe
                WITH child, replace(parentSafe, '\\u0001', '\\\\,') AS parentDN
                WHERE parentDN <> ''
                MATCH (parent:Base {distinguishedname: parentDN})
                MERGE (parent)-[:Contains]->(child)
                RETURN count(*) AS synthesized
                """).single()
                if r and r['synthesized']:
                    logger.info(f"Synthesized {r['synthesized']} Contains edge(s) from DN parentage")

                # Phase 3: parse raw gplink attribute → GpLink edges.
                # Source format: "[LDAP://cn={GUID},cn=policies,…;FLAG][LDAP://…]"
                # We split on '[', strip the trailing ']', take everything
                # before ';' as the LDAP path and the rest as the flag (2=enforced).
                # The CN GUID is extracted and resolved against GPO DNs.
                r = session.run("""
                MATCH (anchor)
                WHERE anchor.gplink IS NOT NULL AND toLower(anchor.gplink) CONTAINS 'cn={'
                WITH anchor, anchor.gplink AS raw
                UNWIND [s IN split(raw, '[') WHERE size(s) > 0] AS seg
                WITH anchor, replace(seg, ']', '') AS clean
                WITH anchor,
                     split(clean, ';')[0] AS ldap_part,
                     coalesce(split(clean, ';')[1], '0') AS flag
                WITH anchor, flag, toUpper(ldap_part) AS up
                WHERE up CONTAINS 'CN={'
                WITH anchor, flag,
                     split(split(up, 'CN={')[1], '}')[0] AS guid
                WHERE guid <> ''
                MATCH (gpo:GPO)
                WHERE toUpper(gpo.distinguishedname) CONTAINS ('CN={' + guid + '}')
                MERGE (gpo)-[r:GpLink]->(anchor)
                SET r.enforced = (flag = '2')
                RETURN count(r) AS gplinks
                """).single()
                if r and r['gplinks']:
                    logger.info(f"Synthesized {r['gplinks']} GpLink edge(s) from raw gplink attribute")

                # Phase 4: flag Domain Controllers. SharpHound-style data often
                # omits the `isdc` property. A computer is a DC if it lives in the
                # Domain Controllers OU (DN contains 'OU=DOMAIN CONTROLLERS') or
                # advertises a Global Catalog SPN (GC/...). Set isdc=true so the
                # DC query and visualizer don't depend on the collector emitting it.
                r = session.run("""
                MATCH (c:Computer)
                WHERE (c.isdc IS NULL OR c.isdc = false)
                  AND (toUpper(c.distinguishedname) CONTAINS 'OU=DOMAIN CONTROLLERS'
                       OR any(s IN c.serviceprincipalnames WHERE toUpper(s) STARTS WITH 'GC/'))
                SET c.isdc = true
                RETURN count(c) AS flagged
                """).single()
                if r and r['flagged']:
                    logger.info(f"Flagged {r['flagged']} computer(s) as Domain Controllers")
        except Exception as e:
            logger.warning(f"DN backfill pass failed: {e}")

    def import_zip(self, file_obj, progress_cb=None):
        self._ensure_schema()
        results = {'files': [], 'nodes': 0, 'relationships': 0, 'errors': []}
        # Normalise to a seekable file-like object without loading into memory.
        if not hasattr(file_obj, 'read'):
            file_obj = open(file_obj, 'rb')
        try:
            with zipfile.ZipFile(file_obj) as zf:
                # Zip-bomb guard: check total decompressed size before extracting
                total_size = sum(i.file_size for i in zf.infolist())
                if total_size > MAX_DECOMPRESSED_BYTES:
                    return {'files': [], 'nodes': 0, 'relationships': 0,
                            'errors': [f'ZIP decompressed size ({total_size} bytes) exceeds limit']}

                # Accept .json at ANY depth in the zip — many collectors nest the
                # files in a folder (e.g. 20260603_BloodHound/computers.json).
                # Only the basename matters for type detection (_sort_key /
                # _guess_type), so nested paths process fine. Skip directory
                # entries (those end in '/', so .endswith('.json') excludes them).
                json_files = [n for n in zf.namelist() if n.endswith('.json')]
                json_files.sort(key=lambda x: self._sort_key(x))
                files_total = len(json_files)
                if files_total == 0:
                    results['errors'].append(
                        'No .json files found in the uploaded archive')
                for fname in json_files:
                    try:
                        if progress_cb:
                            progress_cb(fname, len(results['files']), files_total,
                                        results['nodes'], results['relationships'])
                        content = json.loads(zf.read(fname))
                        r = self._process_file(fname, content)
                        results['files'].append(fname)
                        results['nodes'] += r.get('nodes', 0)
                        results['relationships'] += r.get('relationships', 0)
                        if r.get('errors'):
                            results['errors'].extend(r['errors'])
                        if progress_cb:
                            progress_cb(fname, len(results['files']), files_total,
                                        results['nodes'], results['relationships'])
                    except Exception as e:
                        results['errors'].append(f"{fname}: {str(e)}")
        except zipfile.BadZipFile:
            # Try as single JSON
            try:
                if hasattr(file_obj, 'seek'):
                    file_obj.seek(0)
                content = json.loads(file_obj.read())
                fname = getattr(file_obj, 'filename', 'upload.json')
                if progress_cb:
                    progress_cb(fname, 0, 1, 0, 0)
                r = self._process_file(fname, content)
                results['files'].append(fname)
                results['nodes'] += r.get('nodes', 0)
                results['relationships'] += r.get('relationships', 0)
                if progress_cb:
                    progress_cb(fname, 1, 1, results['nodes'], results['relationships'])
            except Exception as e:
                results['errors'].append(f"Parse error: {str(e)}")
        except Exception as e:
            results['errors'].append(f"ZIP error: {str(e)}")
        # Post-import: backfill domain + synthesize Contains edges from DN parentage.
        # Catches SharpHound-style data where node properties / ChildObjects are sparse.
        # Both passes are idempotent, so re-uploads don't grow the graph.
        self._backfill_from_dn()
        return results

    def _sort_key(self, fname):
        fname_lower = fname.lower()
        for i, t in enumerate(FILE_TYPE_ORDER):
            if t in fname_lower:
                return i
        return len(FILE_TYPE_ORDER)

    def _process_file(self, filename, content):
        meta = content.get('meta', {})
        data_type = meta.get('type', self._guess_type(filename))
        data = content.get('data', [])
        if not data_type or not data:
            return {'nodes': 0, 'relationships': 0, 'errors': []}

        # Use only known labels — reject unknown data types rather than capitalizing user input
        label = TYPE_TO_LABEL.get(data_type.lower())
        if not label:
            logger.warning(f"Unknown data type '{data_type}' in {filename} — skipping")
            return {'nodes': 0, 'relationships': 0, 'errors': [f"Unknown type: {data_type}"]}

        nodes_created = 0
        rels_created = 0
        errors = []

        BATCH = 500
        for i in range(0, len(data), BATCH):
            batch = data[i:i+BATCH]
            try:
                n, r, errs = self._import_batch(batch, label, data_type)
                nodes_created += n
                rels_created += r
                errors.extend(errs)
            except Exception as e:
                errors.append(f"Batch {i}: {str(e)}")
                logger.exception(f"Batch error in {filename}")

        return {'nodes': nodes_created, 'relationships': rels_created, 'errors': errors}

    def _guess_type(self, filename):
        fname = filename.lower()
        for t in FILE_TYPE_ORDER:
            if t in fname:
                return t
        return None

    def _import_batch(self, batch, label, data_type):
        nodes_created = 0
        rels_created = 0
        errors = []

        with self.driver.session() as session:
            # ── Phase 1: nodes ────────────────────────────────────────────────
            node_data = []
            for obj in batch:
                props = obj.get('Properties', {})
                obj_id = obj.get('ObjectIdentifier', props.get('objectid', ''))
                if not obj_id:
                    continue
                props = dict(props) if props else {}
                props['objectid'] = obj_id
                clean_props = {}
                for k, v in props.items():
                    if v is None:
                        continue
                    if isinstance(v, (str, int, float, bool)):
                        clean_props[k.lower()] = v
                    elif isinstance(v, list) and all(isinstance(i, str) for i in v):
                        clean_props[k.lower()] = v
                clean_props['objectid'] = obj_id
                if label in DN_DOMAIN_LABELS and not clean_props.get('domain'):
                    derived = _domain_from_dn(clean_props.get('distinguishedname'))
                    if derived:
                        clean_props['domain'] = derived
                node_data.append(clean_props)

            if node_data:
                query = f"""
                UNWIND $nodes AS props
                MERGE (n:Base {{objectid: props.objectid}})
                REMOVE n:User, n:Computer, n:Group, n:GPO, n:OU, n:Container,
                       n:Domain, n:CertTemplate, n:EnterpriseCA, n:RootCA,
                       n:AIACA, n:NTAuthStore, n:IssuancePolicy
                SET n:{label}, n += props
                """
                try:
                    session.run(query, nodes=node_data)
                    nodes_created = len(node_data)
                except Exception as e:
                    logger.error(f"Node creation error ({label}): {e}")

            # ── Phase 2: collect all relationships across the batch ────────────
            ace_rels   = defaultdict(list)  # rel_type -> [{src, dst, inh}]
            member_rels    = []
            primary_rels   = []
            session_rels   = []
            local_rels = defaultdict(list)  # rel_type -> [{src, dst}]
            delegate_rels  = []
            act_rels       = []
            trust_rels     = []
            trust_targets  = []  # {sid, name} to name foreign-domain stubs
            child_rels     = []
            gpo_link_rels  = []
            sid_hist_rels  = []
            adcs_rels  = defaultdict(list)

            for obj in batch:
                obj_id = obj.get('ObjectIdentifier', obj.get('Properties', {}).get('objectid', ''))
                if not obj_id:
                    continue

                for ace in obj.get('Aces', []):
                    src_id = ace.get('PrincipalSID', '')
                    right  = ace.get('RightName', '')
                    if not src_id or not right or right not in ALLOWED_REL_TYPES:
                        continue
                    ace_rels[right].append({'src': src_id, 'dst': obj_id, 'inh': ace.get('IsInherited', False)})

                for m in obj.get('Members', []):
                    m_id = m.get('ObjectIdentifier', '')
                    if m_id:
                        member_rels.append({'src': m_id, 'dst': obj_id})

                pg = obj.get('PrimaryGroupSid', '')
                if pg:
                    primary_rels.append({'src': obj_id, 'dst': pg})

                sess_data = obj.get('Sessions', {})
                sess_list = sess_data.get('Results', []) if isinstance(sess_data, dict) else (sess_data or [])
                for s in sess_list:
                    u_id = s.get('UserSID', '')
                    if u_id:
                        session_rels.append({'src': u_id, 'dst': obj_id})

                for field, rel in [('LocalAdmins', 'AdminTo'), ('RemoteDesktopUsers', 'CanRDP'),
                                    ('PSRemoteUsers', 'CanPSRemote'), ('DcomUsers', 'ExecuteDCOM')]:
                    col = obj.get(field, {})
                    col_list = col.get('Results', []) if isinstance(col, dict) else (col or [])
                    for item in col_list:
                        i_id = item.get('ObjectIdentifier', '')
                        if i_id:
                            local_rels[rel].append({'src': i_id, 'dst': obj_id})

                for d in obj.get('AllowedToDelegate', []):
                    d_id = d.get('ObjectIdentifier', d) if isinstance(d, dict) else d
                    if d_id:
                        delegate_rels.append({'src': obj_id, 'dst': d_id})

                for a in obj.get('AllowedToAct', []):
                    a_id = a.get('ObjectIdentifier', a) if isinstance(a, dict) else a
                    if a_id:
                        act_rels.append({'src': a_id, 'dst': obj_id})

                for t in obj.get('Trusts', []):
                    t_sid = t.get('TargetDomainSid', t.get('TargetDomainName', ''))
                    if not t_sid:
                        continue
                    # Orient the edge by TrustDirection. BloodHound's TrustedBy:
                    # (A)-[:TrustedBy]->(B) means B trusts A, so principals in A
                    # can access B (attack flows A→B). From the collected domain D
                    # with target T:
                    #   Inbound  → D is trusted by T → (D)-[:TrustedBy]->(T)
                    #   Outbound → T is trusted by D → (T)-[:TrustedBy]->(D)
                    #   Bidirectional → both. Disabled → no traversal, skip.
                    direction = _norm_trust_dir(t.get('TrustDirection', _TRUST_DIR_BIDIR))
                    props = {'tt': _norm_trust_type(t.get('TrustType', '')),
                             'tr': t.get('IsTransitive', False),
                             'sf': t.get('SidFilteringEnabled', False)}
                    if direction in (_TRUST_DIR_INBOUND, _TRUST_DIR_BIDIR):
                        trust_rels.append({'src': obj_id, 'dst': t_sid, **props})
                    if direction in (_TRUST_DIR_OUTBOUND, _TRUST_DIR_BIDIR):
                        trust_rels.append({'src': t_sid, 'dst': obj_id, **props})
                    # The trust carries the target's FQDN — use it to name the
                    # foreign-domain stub so it isn't a nameless SID-only node.
                    t_name = t.get('TargetDomainName', '')
                    if t_name:
                        trust_targets.append({'sid': t_sid, 'name': t_name.upper()})

                for c in obj.get('ChildObjects', []):
                    c_id = c.get('ObjectIdentifier', '')
                    if c_id:
                        child_rels.append({'src': obj_id, 'dst': c_id})

                for lnk in obj.get('Links', []):
                    gpo_id = lnk.get('GUID', lnk.get('ObjectIdentifier', ''))
                    if gpo_id:
                        gpo_link_rels.append({'src': gpo_id, 'dst': obj_id})

                for h in obj.get('HasSIDHistory', []):
                    h_id = h.get('ObjectIdentifier', h) if isinstance(h, dict) else h
                    if h_id:
                        sid_hist_rels.append({'src': obj_id, 'dst': h_id})

                for field, rel in [('IssuedSignedBy', 'IssuedSignedBy'), ('NTAuthStoreFor', 'NTAuthStoreFor'),
                                    ('RootCAFor', 'RootCAFor'), ('TrustedForNTAuth', 'TrustedForNTAuth'),
                                    ('HostsCAService', 'HostsCAService')]:
                    for target in obj.get(field, []):
                        t_id = target.get('ObjectIdentifier', target) if isinstance(target, dict) else target
                        if t_id:
                            adcs_rels[rel].append({'src': obj_id, 'dst': t_id})

            # ── Phase 3: write all relationships as batched UNWINDs ───────────
            _SIMPLE = "UNWIND $rels AS r MERGE (a:Base {objectid: r.src}) MERGE (b:Base {objectid: r.dst})"

            for right, rels in ace_rels.items():
                try:
                    session.run(f"{_SIMPLE} MERGE (a)-[rel:{right}]->(b) SET rel.isinherited = r.inh", rels=rels)
                    rels_created += len(rels)
                except Exception as e:
                    errors.append(f"ACE {right}: {e}")

            for rels, rel_type in [
                (member_rels,   'MemberOf'),
                (session_rels,  'HasSession'),
                (delegate_rels, 'AllowedToDelegate'),
                (act_rels,      'AllowedToAct'),
                (child_rels,    'Contains'),
                (gpo_link_rels, 'GpLink'),
                (sid_hist_rels, 'HasSIDHistory'),
            ]:
                if rels:
                    try:
                        session.run(f"{_SIMPLE} MERGE (a)-[:{rel_type}]->(b)", rels=rels)
                        rels_created += len(rels)
                    except Exception as e:
                        errors.append(f"{rel_type}: {e}")

            if primary_rels:
                try:
                    session.run(f"{_SIMPLE} MERGE (a)-[rel:MemberOf]->(b) SET rel.isprimarygroup = true", rels=primary_rels)
                    rels_created += len(primary_rels)
                except Exception as e:
                    errors.append(f"PrimaryGroup: {e}")

            for rel, rels in local_rels.items():
                if rels:
                    try:
                        session.run(f"{_SIMPLE} MERGE (a)-[:{rel}]->(b)", rels=rels)
                        rels_created += len(rels)
                    except Exception as e:
                        errors.append(f"LocalRel {rel}: {e}")

            if trust_rels:
                try:
                    session.run("""
                        UNWIND $rels AS r
                        MERGE (a:Base {objectid: r.src}) ON CREATE SET a:Domain
                        MERGE (b:Base {objectid: r.dst}) ON CREATE SET b:Domain
                        MERGE (a)-[rel:TrustedBy]->(b)
                        SET rel.trusttype = r.tt, rel.transitive = r.tr, rel.sidfiltering = r.sf
                    """, rels=trust_rels)
                    rels_created += len(trust_rels)
                except Exception as e:
                    errors.append(f"TrustedBy: {e}")

            # Name foreign-domain stubs from the trust's TargetDomainName so the
            # trust map shows FQDNs instead of bare SIDs. Only fills NULL names —
            # never overwrites a collected domain's real name.
            if trust_targets:
                try:
                    session.run("""
                        UNWIND $targets AS t
                        MATCH (d:Base {objectid: t.sid})
                        WHERE d.name IS NULL
                        SET d:Domain, d.name = t.name, d.domain = t.name
                    """, targets=trust_targets)
                except Exception as e:
                    errors.append(f"Trust target naming: {e}")

            for rel, rels in adcs_rels.items():
                if rels:
                    try:
                        session.run(f"{_SIMPLE} MERGE (a)-[:{rel}]->(b)", rels=rels)
                        rels_created += len(rels)
                    except Exception as e:
                        errors.append(f"ADCS {rel}: {e}")

        return nodes_created, rels_created, errors

    def clear_database(self):
        # Delete in batches via CALL {} IN TRANSACTIONS so large graphs don't
        # blow Neo4j's per-transaction memory limit (a single MATCH (n) DETACH
        # DELETE n holds the whole graph in one tx and OOMs).
        # CALL {} IN TRANSACTIONS must run as an auto-commit (implicit) query —
        # NOT inside execute_write — and .consume() is required to actually
        # drive it to completion (session.run is lazy; an unconsumed result is
        # discarded on session close, silently deleting nothing).
        with self.driver.session() as session:
            # Phase 1: drop all relationships in batches (cheap per row, and
            # avoids the DETACH DELETE memory spike on high-degree nodes).
            session.run(
                "MATCH ()-[r]->() CALL { WITH r DELETE r } IN TRANSACTIONS OF 10000 ROWS"
            ).consume()
            # Phase 2: drop the now-disconnected nodes in batches.
            session.run(
                "MATCH (n) CALL { WITH n DELETE n } IN TRANSACTIONS OF 10000 ROWS"
            ).consume()

    def get_stats(self):
        stats = {}
        # AD object labels — filter `name IS NOT NULL` so the chip count
        # matches what shows up in the list views (which already filter
        # out namespaced BUILTIN-group stubs and other name-less ACE
        # reference targets).
        ad_object_labels = ['User', 'Computer', 'Group', 'Domain', 'GPO',
                            'OU', 'Container']
        # ADCS labels — these are only imported from their own JSON files,
        # never stub-created via ACE references, so no filter needed.
        adcs_labels = ['CertTemplate', 'EnterpriseCA', 'RootCA',
                       'AIACA', 'NTAuthStore', 'IssuancePolicy']
        with self.driver.session() as session:
            for lbl in ad_object_labels:
                try:
                    r = session.run(f"MATCH (n:{lbl}) WHERE n.name IS NOT NULL RETURN count(n) AS c").single()
                    stats[lbl] = r['c'] if r else 0
                except Exception:
                    stats[lbl] = 0
            for lbl in adcs_labels:
                try:
                    r = session.run(f"MATCH (n:{lbl}) RETURN count(n) AS c").single()
                    stats[lbl] = r['c'] if r else 0
                except Exception:
                    stats[lbl] = 0
            try:
                r = session.run("MATCH ()-[r]->() RETURN count(r) AS c").single()
                stats['Relationships'] = r['c'] if r else 0
            except Exception:
                stats['Relationships'] = 0
        return stats
