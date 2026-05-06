import json
import zipfile
import io
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
    'aiaca': 'AIACA',
    'rootca': 'RootCA',
    'enterpriseca': 'EnterpriseCA',
    'ntauthstore': 'NTAuthStore',
    'certtemplate': 'CertTemplate',
    'issuancepolicy': 'IssuancePolicy',
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
                   'certtemplate', 'enterpriseca', 'rootca', 'aiaca', 'ntauthstore']


class BloodHoundImporter:
    def __init__(self, driver):
        self.driver = driver

    def import_zip(self, file_obj):
        results = {'files': [], 'nodes': 0, 'relationships': 0, 'errors': []}
        try:
            data = file_obj.read() if hasattr(file_obj, 'read') else open(file_obj, 'rb').read()

            with zipfile.ZipFile(io.BytesIO(data)) as zf:
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
                content = json.loads(data)
                fname = getattr(file_obj, 'filename', 'upload.json')
                r = self._process_file(fname, content)
                results['files'].append(fname)
                results['nodes'] += r.get('nodes', 0)
                results['relationships'] += r.get('relationships', 0)
            except Exception as e:
                results['errors'].append(f"Parse error: {str(e)}")
        except Exception as e:
            results['errors'].append(f"ZIP error: {str(e)}")
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
                node_data.append(clean_props)

            if node_data:
                query = f"""
                UNWIND $nodes AS props
                MERGE (n:{label} {{objectid: props.objectid}})
                SET n += props
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
                    MERGE (src:{src_label} {{objectid: $src}})
                    MERGE (dst:{label} {{objectid: $dst}})
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
                    MERGE (src:{m_label} {{objectid: $src}})
                    MERGE (dst:{label} {{objectid: $dst}})
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
                    MERGE (src:{label} {{objectid: $src}})
                    MERGE (dst:Group {{objectid: $dst}})
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
                        MERGE (u:User {{objectid: $uid}})
                        MERGE (c:{label} {{objectid: $cid}})
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
                        MERGE (src:{i_label} {{objectid: $src}})
                        MERGE (dst:{label} {{objectid: $dst}})
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
                        MERGE (src:{label} {{objectid: $src}})
                        MERGE (dst:{d_label} {{objectid: $dst}})
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
                        MERGE (src:{a_label} {{objectid: $src}})
                        MERGE (dst:{label} {{objectid: $dst}})
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
                        MERGE (src:Domain {objectid: $src})
                        MERGE (dst:Domain {objectid: $dst})
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
                        MERGE (src:{label} {{objectid: $src}})
                        MERGE (dst:{c_label} {{objectid: $dst}})
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
                        MERGE (gpo:GPO {{objectid: $gpo}})
                        MERGE (dst:{label} {{objectid: $dst}})
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
                        MERGE (src:{label} {{objectid: $src}})
                        MERGE (dst:{h_label} {{objectid: $dst}})
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
                            MERGE (src:{label} {{objectid: $src}})
                            MERGE (dst:{t_label} {{objectid: $dst}})
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
        labels = ['User', 'Computer', 'Group', 'Domain', 'GPO', 'OU',
                  'CertTemplate', 'EnterpriseCA', 'RootCA']
        with self.driver.session() as session:
            for lbl in labels:
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
