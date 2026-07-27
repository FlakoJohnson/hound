"""Import → export → re-import round-trip invariants.

These run against a real Neo4j because that is where the behaviour actually
lives: the importer and exporter are almost entirely Cypher, and mocking the
driver would only assert that the mocks match the code. Every test writes into
an isolated domain and removes it afterwards, so an instance holding real data
is safe to point this at.

    NEO4J_URI=bolt://localhost:7687 NEO4J_USER=neo4j NEO4J_PASS=... \
        python -m pytest tests/ -v

Skipped automatically when no Neo4j is reachable.
"""

import io
import json
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from exporter import BloodHoundExporter          # noqa: E402
from importer import BloodHoundImporter          # noqa: E402
from graphquery import get_stats                 # noqa: E402

TEST_DOMAIN = 'ROUNDTRIP.TEST'
TEST_SID = 'S-1-5-21-9990001-9990002-9990003'


def _driver():
    try:
        from neo4j import GraphDatabase
        d = GraphDatabase.driver(
            os.environ.get('NEO4J_URI', 'bolt://localhost:7687'),
            auth=(os.environ.get('NEO4J_USER', 'neo4j'),
                  os.environ.get('NEO4J_PASS', 'bloodhound')))
        d.verify_connectivity()
        return d
    except Exception:
        return None


@pytest.fixture(scope='module')
def driver():
    d = _driver()
    if d is None:
        pytest.skip('no Neo4j reachable')
    yield d
    with d.session() as s:
        s.run('MATCH (n) WHERE n.domain = $d DETACH DELETE n', d=TEST_DOMAIN)
    d.close()


def _props(oid, name, **extra):
    p = {'objectid': oid, 'name': name, 'domain': TEST_DOMAIN,
         'domainsid': TEST_SID}
    p.update(extra)
    return p


def _fixture_zip():
    """A miniature collection exercising every field the exporter rebuilds."""
    user = f'{TEST_SID}-1001'
    grp = f'{TEST_SID}-513'
    admins = f'{TEST_SID}-512'
    comp = f'{TEST_SID}-1002'
    ou = 'OU-ROUNDTRIP-0001'
    # syncer holds both replication rights, so DCSync must be synthesized for it.
    # halfsync holds only GetChanges, which alone cannot DCSync — it must not get
    # the edge. That pair is the whole point of the composite.
    syncer = f'{TEST_SID}-1003'
    halfsync = f'{TEST_SID}-1004'

    # The explicit membership deliberately targets a *different* group from the
    # primary one. Both kinds of membership become the same (a)-[:MemberOf]->(b)
    # edge, so a principal that is both an explicit member and a primary-group
    # member of one group collapses to a single edge and exports only as
    # PrimaryGroupSID. AD does not enumerate primary-group members in `member`,
    # so that overlap does not occur in collected data.

    files = {
        'domains.json': [{
            'ObjectIdentifier': TEST_SID,
            'Properties': _props(TEST_SID, TEST_DOMAIN, machineaccountquota=10),
            'Aces': [
                {'PrincipalSID': user, 'PrincipalType': 'User',
                 'RightName': 'GenericAll', 'IsInherited': False},
                {'PrincipalSID': syncer, 'PrincipalType': 'User',
                 'RightName': 'GetChanges', 'IsInherited': False},
                {'PrincipalSID': syncer, 'PrincipalType': 'User',
                 'RightName': 'GetChangesAll', 'IsInherited': False},
                {'PrincipalSID': halfsync, 'PrincipalType': 'User',
                 'RightName': 'GetChanges', 'IsInherited': False},
            ],
            'ChildObjects': [{'ObjectIdentifier': ou, 'ObjectType': 'OU'}],
            'Links': [], 'Trusts': [],
        }],
        'users.json': [
            {
                'ObjectIdentifier': user,
                'Properties': _props(user, f'ALICE@{TEST_DOMAIN}'),
                # The casing that silently dropped every implicit membership.
                'PrimaryGroupSID': grp,
                'Aces': [],
            },
            {
                'ObjectIdentifier': syncer,
                'Properties': _props(syncer, f'SYNCER@{TEST_DOMAIN}'),
                'Aces': [],
            },
            {
                'ObjectIdentifier': halfsync,
                'Properties': _props(halfsync, f'HALFSYNC@{TEST_DOMAIN}'),
                'Aces': [],
            },
        ],
        'computers.json': [{
            'ObjectIdentifier': comp,
            'Properties': _props(comp, f'PC1.{TEST_DOMAIN}'),
            'PrimaryGroupSID': grp,
            'Aces': [{'PrincipalSID': user, 'PrincipalType': 'User',
                      'RightName': 'WriteDacl', 'IsInherited': True}],
            # v6 shape: BUILTIN groups keyed by RID, no legacy per-field arrays.
            # alice is in both Administrators and Remote Desktop Users; halfsync
            # is only in RDU and is absent from the URA list, so it must not get
            # a CanRDP edge.
            'LocalGroups': [
                {'ObjectIdentifier': f'{comp}-544', 'Name': 'ADMINISTRATORS',
                 'Collected': True, 'FailureReason': None, 'LocalNames': [],
                 'Results': [{'ObjectIdentifier': user, 'ObjectType': 'User'}]},
                {'ObjectIdentifier': f'{comp}-555', 'Name': 'REMOTE DESKTOP USERS',
                 'Collected': True, 'FailureReason': None, 'LocalNames': [],
                 'Results': [{'ObjectIdentifier': user, 'ObjectType': 'User'},
                             {'ObjectIdentifier': halfsync, 'ObjectType': 'User'}]},
                {'ObjectIdentifier': f'{comp}-580', 'Name': 'REMOTE MANAGEMENT USERS',
                 'Collected': True, 'FailureReason': None, 'LocalNames': [],
                 'Results': [{'ObjectIdentifier': user, 'ObjectType': 'User'}]},
            ],
            'UserRights': [
                {'Privilege': 'SeRemoteInteractiveLogonRight', 'Collected': True,
                 'FailureReason': None, 'LocalNames': [],
                 'Results': [{'ObjectIdentifier': user, 'ObjectType': 'User'}]},
            ],
        }],
        'groups.json': [
            {
                'ObjectIdentifier': grp,
                'Properties': _props(grp, f'DOMAIN USERS@{TEST_DOMAIN}'),
                'Members': [],
                'Aces': [],
            },
            {
                'ObjectIdentifier': admins,
                'Properties': _props(admins, f'DOMAIN ADMINS@{TEST_DOMAIN}'),
                'Members': [{'ObjectIdentifier': user, 'ObjectType': 'User'}],
                'Aces': [],
            },
        ],
        'ous.json': [{
            'ObjectIdentifier': ou,
            'Properties': _props(ou, f'TESTOU@{TEST_DOMAIN}'),
            'ChildObjects': [{'ObjectIdentifier': comp, 'ObjectType': 'Computer'}],
            'Aces': [], 'Links': [],
        }],
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        for name, data in files.items():
            zf.writestr(name, json.dumps({
                'data': data,
                'meta': {'type': name[:-5], 'count': len(data),
                         'version': 6, 'methods': 0},
            }))
    buf.seek(0)
    return buf


def _counts(driver):
    with driver.session() as s:
        nodes = s.run('MATCH (n) WHERE n.domain = $d RETURN count(n) AS c',
                      d=TEST_DOMAIN).single()['c']
        rels = s.run('MATCH (a)-[r]->(b) WHERE a.domain = $d OR b.domain = $d '
                     'RETURN count(r) AS c', d=TEST_DOMAIN).single()['c']
    return nodes, rels


@pytest.fixture(scope='module')
def imported(driver):
    BloodHoundImporter(driver).import_zip(_fixture_zip())
    return driver


def test_primary_group_membership_is_created(imported):
    """Regression: PrimaryGroupSid vs PrimaryGroupSID dropped these silently."""
    with imported.session() as s:
        n = s.run(
            'MATCH (x)-[r:MemberOf {isprimarygroup:true}]->(g) '
            'WHERE g.objectid = $g RETURN count(x) AS c',
            g=f'{TEST_SID}-513').single()['c']
    assert n == 2, 'user and computer should both land in Domain Users'


def test_ace_edges_are_marked_isacl(imported):
    """BloodHound-idiomatic `WHERE r.isacl = true` must work against Hound."""
    with imported.session() as s:
        n = s.run('MATCH ()-[r]->(b) WHERE b.domain = $d AND r.isacl = true '
                  'RETURN count(r) AS c', d=TEST_DOMAIN).single()['c']
    assert n == 5, '4 domain ACEs + WriteDacl on the computer'


def test_dcsync_is_synthesized_only_for_both_rights(imported):
    """DCSync needs GetChanges AND GetChangesAll; either alone must not qualify."""
    with imported.session() as s:
        holders = [r['n'] for r in s.run(
            'MATCH (n)-[:DCSync]->(d:Domain) WHERE d.domain = $d '
            'RETURN n.name AS n', d=TEST_DOMAIN)]
    assert holders == [f'SYNCER@{TEST_DOMAIN}'], \
        'only the principal holding both replication rights'


def test_bloodhound_dcsync_query_works_verbatim(imported):
    """BloodHound's own shipped query must return results against Hound."""
    with imported.session() as s:
        rows = [r['n'] for r in s.run(
            'MATCH (n)-[:DCSync|AllExtendedRights|GenericAll]->(d:Domain) '
            'WHERE d.domain = $d RETURN DISTINCT n.name AS n', d=TEST_DOMAIN)]
    assert sorted(rows) == sorted([f'SYNCER@{TEST_DOMAIN}', f'ALICE@{TEST_DOMAIN}'])


def test_local_groups_map_to_lateral_edges_by_rid(imported):
    """v6 data has no LocalAdmins/RemoteDesktopUsers arrays — only LocalGroups
    keyed by RID. Reading just the legacy fields yielded zero lateral edges."""
    with imported.session() as s:
        rows = {r['rel']: r['c'] for r in s.run(
            'MATCH ()-[r:AdminTo|CanRDP|CanPSRemote|ExecuteDCOM]->(c:Computer) '
            'WHERE c.domain = $d RETURN type(r) AS rel, count(r) AS c',
            d=TEST_DOMAIN)}
    assert rows.get('AdminTo') == 1, 'from the -544 group'
    assert rows.get('CanPSRemote') == 1, 'from the -580 group'
    assert rows.get('ExecuteDCOM') is None, 'no -562 group in the fixture'


def test_canrdp_respects_user_rights_assignment(imported):
    """Remote Desktop Users membership alone must not grant CanRDP when the
    logon right has been withdrawn — BloodHound enforces the same."""
    with imported.session() as s:
        holders = sorted(r['n'] for r in s.run(
            'MATCH (n)-[:CanRDP]->(c:Computer) WHERE c.domain = $d '
            'RETURN n.name AS n', d=TEST_DOMAIN))
    assert holders == [f'ALICE@{TEST_DOMAIN}'], \
        'halfsync is in RDU but absent from SeRemoteInteractiveLogonRight'


def test_synthesized_edges_are_not_exported_as_aces(imported):
    """A derived DCSync edge must not become a fabricated ACE in an export."""
    blob, _ = BloodHoundExporter(imported).export_zip(domain=TEST_DOMAIN)
    z = zipfile.ZipFile(io.BytesIO(blob))
    rights = [a['RightName']
              for name in z.namelist()
              for obj in json.loads(z.read(name))['data']
              for a in (obj.get('Aces') or [])]
    assert 'DCSync' not in rights
    assert 'GetChanges' in rights and 'GetChangesAll' in rights


def test_export_matches_graph(imported):
    blob, stats = BloodHoundExporter(imported).export_zip(domain=TEST_DOMAIN)
    z = zipfile.ZipFile(io.BytesIO(blob))

    aces = members = primary = children = 0
    for name in z.namelist():
        for obj in json.loads(z.read(name))['data']:
            aces += len(obj.get('Aces') or [])
            members += len(obj.get('Members') or [])
            children += len(obj.get('ChildObjects') or [])
            if obj.get('PrimaryGroupSID'):
                primary += 1

    assert stats['nodes'] == 8
    # GenericAll + 3 replication ACEs on the domain, WriteDacl on the computer.
    # The synthesized DCSync edge must NOT appear as a fifth.
    assert aces == 5
    assert primary == 2, 'primary group belongs on the member, not in Members'
    assert members == 1, 'only the explicit Domain Admins membership'
    assert children == 2


def test_export_preserves_scalar_properties(imported):
    blob, _ = BloodHoundExporter(imported).export_zip(domain=TEST_DOMAIN)
    z = zipfile.ZipFile(io.BytesIO(blob))
    dom = json.loads(z.read('domains.json'))['data'][0]
    assert dom['Properties']['machineaccountquota'] == 10
    assert dom['Properties']['name'] == TEST_DOMAIN


def test_export_omits_operator_notes(imported):
    """hound_notes must never leave in an export handed to a third party."""
    secret = 'OPERATOR-ONLY-NOTE'
    with imported.session() as s:
        s.run('MATCH (n) WHERE n.objectid = $o SET n.hound_notes = $t',
              o=f'{TEST_SID}-1001', t=secret)
    try:
        blob, _ = BloodHoundExporter(imported).export_zip(domain=TEST_DOMAIN)
        assert secret.encode() not in blob
    finally:
        with imported.session() as s:
            s.run('MATCH (n) WHERE n.objectid = $o REMOVE n.hound_notes',
                  o=f'{TEST_SID}-1001')


def test_local_groups_survive_a_round_trip(imported):
    """Exported LocalGroups must be RID-keyed, or re-import drops the edges."""
    blob, _ = BloodHoundExporter(imported).export_zip(domain=TEST_DOMAIN)
    z = zipfile.ZipFile(io.BytesIO(blob))
    comp = json.loads(z.read('computers.json'))['data'][0]
    ids = {g['ObjectIdentifier'].rsplit('-', 1)[-1] for g in comp['LocalGroups']}
    assert {'544', '555', '580'} <= ids, f'expected RID-keyed groups, got {ids}'

    BloodHoundImporter(imported).import_zip(io.BytesIO(blob))
    with imported.session() as s:
        n = s.run('MATCH ()-[r:AdminTo|CanRDP|CanPSRemote]->(c:Computer) '
                  'WHERE c.domain = $d RETURN count(r) AS c',
                  d=TEST_DOMAIN).single()['c']
    assert n == 3, 'AdminTo + CanRDP + CanPSRemote preserved, none duplicated'


def test_roundtrip_is_idempotent(imported):
    """Re-importing an export must not grow or shrink the graph."""
    before = _counts(imported)
    blob, _ = BloodHoundExporter(imported).export_zip(domain=TEST_DOMAIN)
    BloodHoundImporter(imported).import_zip(io.BytesIO(blob))
    assert _counts(imported) == before


def test_stats_scope_to_domain(imported):
    scoped = get_stats(imported, domain=TEST_DOMAIN)
    assert scoped['User'] == 3
    assert scoped['Computer'] == 1
    assert scoped['OU'] == 1
    assert scoped['Domain'] == 1
    total = get_stats(imported)
    assert total['User'] >= scoped['User']


def test_export_to_file_matches_in_memory(imported, tmp_path):
    out = tmp_path / 'export.zip'
    _, stats = BloodHoundExporter(imported).export_zip(
        domain=TEST_DOMAIN, out_path=str(out))
    assert out.exists() and out.stat().st_size > 0
    blob, mem_stats = BloodHoundExporter(imported).export_zip(domain=TEST_DOMAIN)
    assert stats == mem_stats
    assert zipfile.ZipFile(out).namelist() == zipfile.ZipFile(io.BytesIO(blob)).namelist()
