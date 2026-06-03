import json
import zipfile
import logging

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
        # Run the backfills once (idempotent on subsequent calls).
        self._backfill_from_dn()

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

                # Match direct parent by taking the longest DN that is a suffix
                # of the child DN. Using ENDS WITH instead of splitting on ','
                # handles escaped commas in CN values (e.g. last-name-first format
                # CN=SMITH\, JOHN,...). Taking only collect(parent)[0] after ordering
                # by DN length descending ensures we link only the immediate parent,
                # not grandparent/ancestor OUs which would also match the suffix check.
                r = session.run("""
                MATCH (child)
                WHERE child.distinguishedname IS NOT NULL
                  AND NOT EXISTS { MATCH ()-[:Contains]->(child) }
                MATCH (parent)
                WHERE parent.distinguishedname IS NOT NULL
                  AND parent.distinguishedname <> child.distinguishedname
                  AND toUpper(child.distinguishedname)
                      ENDS WITH (',' + toUpper(parent.distinguishedname))
                WITH child, parent ORDER BY size(parent.distinguishedname) DESC
                WITH child, collect(parent)[0] AS directParent
                MERGE (directParent)-[:Contains]->(child)
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
        except Exception as e:
            logger.warning(f"DN backfill pass failed: {e}")

    def import_zip(self, file_obj):
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

                json_files = [n for n in zf.namelist()
                              if n.endswith('.json') and '/' not in n.strip('/')]
                json_files.sort(key=lambda x: self._sort_key(x))
                for fname in json_files:
                    try:
                        content = json.loads(zf.read(fname))
                        r = self._process_file(fname, content)
                        results['files'].append(fname)
                        results['nodes'] += r.get('nodes', 0)
                        results['relationships'] += r.get('relationships', 0)
                        if r.get('errors'):
                            results['errors'].extend(r['errors'])
                    except Exception as e:
                        results['errors'].append(f"{fname}: {str(e)}")
        except zipfile.BadZipFile:
            # Try as single JSON
            try:
                if hasattr(file_obj, 'seek'):
                    file_obj.seek(0)
                content = json.loads(file_obj.read())
                fname = getattr(file_obj, 'filename', 'upload.json')
                r = self._process_file(fname, content)
                results['files'].append(fname)
                results['nodes'] += r.get('nodes', 0)
                results['relationships'] += r.get('relationships', 0)
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
                n, r = self._import_batch(batch, label, data_type)
                nodes_created += n
                rels_created += r
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

        with self.driver.session() as session:
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
                # SharpHound zips don't emit a `domain` property on Container /
                # OU nodes (and sometimes others); derive it from the DN so the
                # tree visualizer's domain filter and the stats sidebar don't
                # silently drop them.
                if label in DN_DOMAIN_LABELS and not clean_props.get('domain'):
                    derived = _domain_from_dn(clean_props.get('distinguishedname'))
                    if derived:
                        clean_props['domain'] = derived
                node_data.append(clean_props)

            if node_data:
                # MERGE on :Base so existing stubs (from earlier Contains/ACE refs)
                # get the specific label added rather than a duplicate node created.
                # REMOVE other AD-type labels first — the file we're importing is
                # authoritative for this object's actual type (an earlier FSP
                # Contains edge may have asserted the wrong type, e.g. User on a
                # cross-domain Group; we shouldn't keep that leftover label).
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

            for obj in batch:
                obj_id = obj.get('ObjectIdentifier', obj.get('Properties', {}).get('objectid', ''))
                if not obj_id:
                    continue
                try:
                    r = self._create_relationships(session, obj, obj_id, label)
                    rels_created += r
                except Exception as e:
                    logger.debug(f"Rel error for {obj_id}: {e}")

        return nodes_created, rels_created

    def _create_relationships(self, session, obj, obj_id, label):
        count = 0

        # --- ACEs ---
        for ace in obj.get('Aces', []):
            src_id = ace.get('PrincipalSID', '')
            right = ace.get('RightName', '')
            p_type = ace.get('PrincipalType', 'Base')
            if not src_id or not right:
                continue
            # Validate relationship type against allowlist before interpolating into Cypher
            if right not in ALLOWED_REL_TYPES:
                logger.debug(f"Skipping unknown ACE RightName: {right!r}")
                continue
            src_label = TYPE_TO_LABEL.get(p_type.lower(), 'Base')
            inherited = ace.get('IsInherited', False)
            try:
                session.run(f"""
                    MERGE (src:Base {{objectid: $src}})
                    ON CREATE SET src:{src_label}
                    MERGE (dst:Base {{objectid: $dst}})
                    ON CREATE SET dst:{label}
                    MERGE (src)-[r:{right}]->(dst)
                    SET r.isinherited = $inh
                """, src=src_id, dst=obj_id, inh=inherited)
                count += 1
            except Exception:
                pass

        # --- Group Members ---
        for m in obj.get('Members', []):
            m_id = m.get('ObjectIdentifier', '')
            m_type = m.get('ObjectType', 'Base')
            if not m_id:
                continue
            m_label = TYPE_TO_LABEL.get(m_type.lower(), 'Base')
            try:
                session.run(f"""
                    MERGE (src:Base {{objectid: $src}})
                    ON CREATE SET src:{m_label}
                    MERGE (dst:Base {{objectid: $dst}})
                    ON CREATE SET dst:{label}
                    MERGE (src)-[:MemberOf]->(dst)
                """, src=m_id, dst=obj_id)
                count += 1
            except Exception:
                pass

        # --- Primary Group ---
        pg = obj.get('PrimaryGroupSid', '')
        if pg:
            try:
                session.run(f"""
                    MERGE (src:Base {{objectid: $src}})
                    ON CREATE SET src:{label}
                    MERGE (dst:Base {{objectid: $dst}})
                    ON CREATE SET dst:Group
                    MERGE (src)-[:MemberOf {{isprimarygroup: true}}]->(dst)
                """, src=obj_id, dst=pg)
                count += 1
            except Exception:
                pass

        # --- Sessions ---
        sessions = obj.get('Sessions', {})
        sess_list = sessions.get('Results', []) if isinstance(sessions, dict) else (sessions or [])
        for s in sess_list:
            u_id = s.get('UserSID', '')
            if u_id:
                try:
                    session.run(f"""
                        MERGE (u:Base {{objectid: $uid}})
                        ON CREATE SET u:User
                        MERGE (c:Base {{objectid: $cid}})
                        ON CREATE SET c:{label}
                        MERGE (u)-[:HasSession]->(c)
                    """, uid=u_id, cid=obj_id)
                    count += 1
                except Exception:
                    pass

        # --- Privilege / Local Group Collections (hardcoded rel types — not user input) ---
        collection_map = {
            'LocalAdmins': 'AdminTo',
            'RemoteDesktopUsers': 'CanRDP',
            'PSRemoteUsers': 'CanPSRemote',
            'DcomUsers': 'ExecuteDCOM',
        }
        for field, rel in collection_map.items():
            col = obj.get(field, {})
            col_list = col.get('Results', []) if isinstance(col, dict) else (col or [])
            for item in col_list:
                i_id = item.get('ObjectIdentifier', '')
                i_type = item.get('ObjectType', 'Base')
                if not i_id:
                    continue
                i_label = TYPE_TO_LABEL.get(i_type.lower(), 'Base')
                try:
                    session.run(f"""
                        MERGE (src:Base {{objectid: $src}})
                        ON CREATE SET src:{i_label}
                        MERGE (dst:Base {{objectid: $dst}})
                        ON CREATE SET dst:{label}
                        MERGE (src)-[:{rel}]->(dst)
                    """, src=i_id, dst=obj_id)
                    count += 1
                except Exception:
                    pass

        # --- AllowedToDelegate ---
        for d in obj.get('AllowedToDelegate', []):
            d_id = d.get('ObjectIdentifier', d) if isinstance(d, dict) else d
            d_type = d.get('ObjectType', 'Computer') if isinstance(d, dict) else 'Computer'
            d_label = TYPE_TO_LABEL.get(d_type.lower(), 'Computer')
            if d_id:
                try:
                    session.run(f"""
                        MERGE (src:Base {{objectid: $src}})
                        ON CREATE SET src:{label}
                        MERGE (dst:Base {{objectid: $dst}})
                        ON CREATE SET dst:{d_label}
                        MERGE (src)-[:AllowedToDelegate]->(dst)
                    """, src=obj_id, dst=d_id)
                    count += 1
                except Exception:
                    pass

        # --- AllowedToAct (RBCD) ---
        for a in obj.get('AllowedToAct', []):
            a_id = a.get('ObjectIdentifier', a) if isinstance(a, dict) else a
            a_type = a.get('ObjectType', 'Computer') if isinstance(a, dict) else 'Computer'
            a_label = TYPE_TO_LABEL.get(a_type.lower(), 'Computer')
            if a_id:
                try:
                    session.run(f"""
                        MERGE (src:Base {{objectid: $src}})
                        ON CREATE SET src:{a_label}
                        MERGE (dst:Base {{objectid: $dst}})
                        ON CREATE SET dst:{label}
                        MERGE (src)-[:AllowedToAct]->(dst)
                    """, src=a_id, dst=obj_id)
                    count += 1
                except Exception:
                    pass

        # --- Domain Trusts ---
        for t in obj.get('Trusts', []):
            t_sid = t.get('TargetDomainSid', t.get('TargetDomainName', ''))
            if t_sid:
                try:
                    session.run("""
                        MERGE (src:Base {objectid: $src})
                        ON CREATE SET src:Domain
                        MERGE (dst:Base {objectid: $dst})
                        ON CREATE SET dst:Domain
                        MERGE (src)-[r:TrustedBy]->(dst)
                        SET r.trusttype = $tt, r.transitive = $tr, r.sidfiltering = $sf
                    """, src=obj_id, dst=t_sid,
                         tt=t.get('TrustType', ''), tr=t.get('IsTransitive', False),
                         sf=t.get('SidFilteringEnabled', False))
                    count += 1
                except Exception:
                    pass

        # --- ChildObjects / Contains ---
        for c in obj.get('ChildObjects', []):
            c_id = c.get('ObjectIdentifier', '')
            c_type = c.get('ObjectType', 'Base')
            c_label = TYPE_TO_LABEL.get(c_type.lower(), 'Base')
            if c_id:
                try:
                    session.run(f"""
                        MERGE (src:Base {{objectid: $src}})
                        ON CREATE SET src:{label}
                        MERGE (dst:Base {{objectid: $dst}})
                        ON CREATE SET dst:{c_label}
                        MERGE (src)-[:Contains]->(dst)
                    """, src=obj_id, dst=c_id)
                    count += 1
                except Exception:
                    pass

        # --- GPO Links ---
        for lnk in obj.get('Links', []):
            gpo_id = lnk.get('GUID', lnk.get('ObjectIdentifier', ''))
            if gpo_id:
                try:
                    session.run(f"""
                        MERGE (gpo:Base {{objectid: $gpo}})
                        ON CREATE SET gpo:GPO
                        MERGE (dst:Base {{objectid: $dst}})
                        ON CREATE SET dst:{label}
                        MERGE (gpo)-[:GpLink]->(dst)
                    """, gpo=gpo_id, dst=obj_id)
                    count += 1
                except Exception:
                    pass

        # --- HasSIDHistory ---
        for h in obj.get('HasSIDHistory', []):
            h_id = h.get('ObjectIdentifier', h) if isinstance(h, dict) else h
            h_type = h.get('ObjectType', 'User') if isinstance(h, dict) else 'User'
            h_label = TYPE_TO_LABEL.get(h_type.lower(), 'User')
            if h_id:
                try:
                    session.run(f"""
                        MERGE (src:Base {{objectid: $src}})
                        ON CREATE SET src:{label}
                        MERGE (dst:Base {{objectid: $dst}})
                        ON CREATE SET dst:{h_label}
                        MERGE (src)-[:HasSIDHistory]->(dst)
                    """, src=obj_id, dst=h_id)
                    count += 1
                except Exception:
                    pass

        # --- ADCS relationships (all hardcoded rel types) ---
        for field, rel in [('IssuedSignedBy', 'IssuedSignedBy'), ('NTAuthStoreFor', 'NTAuthStoreFor'),
                            ('RootCAFor', 'RootCAFor'), ('TrustedForNTAuth', 'TrustedForNTAuth'),
                            ('HostsCAService', 'HostsCAService')]:
            for target in obj.get(field, []):
                t_id = target.get('ObjectIdentifier', target) if isinstance(target, dict) else target
                t_type = target.get('ObjectType', 'Base') if isinstance(target, dict) else 'Base'
                t_label = TYPE_TO_LABEL.get(t_type.lower(), 'Base')
                if t_id:
                    try:
                        session.run(f"""
                            MERGE (src:Base {{objectid: $src}})
                            ON CREATE SET src:{label}
                            MERGE (dst:Base {{objectid: $dst}})
                            ON CREATE SET dst:{t_label}
                            MERGE (src)-[:{rel}]->(dst)
                        """, src=obj_id, dst=t_id)
                        count += 1
                    except Exception:
                        pass

        return count

    def clear_database(self):
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")

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
