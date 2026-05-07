QUERIES = {
    "Domain Recon": [
        {
            "id": "da_users",
            "name": "All Domain Admins",
            "description": "All users that are members of Domain Admins (direct or nested)",
            "cypher": """MATCH p=(u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.name =~ '(?i)domain admins@.*'
RETURN u.name AS User, u.domain AS Domain, u.enabled AS Enabled, u.admincount AS AdminCount
ORDER BY Domain, User"""
        },
        {
            "id": "dcs",
            "name": "Domain Controllers",
            "description": "All Domain Controllers",
            "cypher": """MATCH (c:Computer)
WHERE c.isdc = true
RETURN c.name AS Computer, c.domain AS Domain, c.operatingsystem AS OS, c.enabled AS Enabled
ORDER BY Domain, Computer"""
        },
        {
            "id": "high_value",
            "name": "High Value Targets",
            "description": "All objects marked as high value in this dataset",
            "cypher": """MATCH (n)
WHERE n.highvalue = true
RETURN labels(n)[0] AS Type, n.name AS Name, n.domain AS Domain
ORDER BY Type, Domain, Name"""
        },
        {
            "id": "domain_trusts",
            "name": "Domain Trust Map",
            "description": "All domain trust relationships — spot cross-domain attack paths",
            "cypher": """MATCH p=(d1:Domain)-[r:TrustedBy]->(d2:Domain)
RETURN d1.name AS Domain, d2.name AS TrustedBy,
       r.trusttype AS TrustType, r.transitive AS Transitive, r.sidfiltering AS SIDFiltering
ORDER BY Domain"""
        },
        {
            "id": "enterprise_admins",
            "name": "Enterprise Admins",
            "description": "All members of Enterprise Admins (forest-wide DA equivalent)",
            "cypher": """MATCH p=(u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.name =~ '(?i)enterprise admins@.*'
RETURN u.name AS User, u.domain AS Domain, u.enabled AS Enabled
ORDER BY Domain, User"""
        },
        {
            "id": "privileged_summary",
            "name": "Privileged Groups Summary",
            "description": "Member count in all high-privilege built-in groups",
            "cypher": """MATCH (g:Group)
WHERE g.name =~ '(?i)(domain admins|enterprise admins|schema admins|administrators|backup operators|account operators|print operators|server operators|group policy creator owners|dnsadmins)@.*'
OPTIONAL MATCH (u)-[:MemberOf*1..]->(g)
RETURN g.name AS Group, count(DISTINCT u) AS MemberCount
ORDER BY MemberCount DESC"""
        },
        {
            "id": "gpos",
            "name": "All GPOs",
            "description": "All Group Policy Objects — useful for GPO abuse paths",
            "cypher": """MATCH (g:GPO)
RETURN g.name AS GPO, g.domain AS Domain, g.objectid AS GUID, g.gpcpath AS GPCPath
ORDER BY Domain, GPO"""
        },
        {
            "id": "gpo_links",
            "name": "GPO Links (applied to OUs)",
            "description": "Which GPOs are linked to which OUs — shows GPO scope and attack surface",
            "cypher": """MATCH (g:GPO)-[:GpLink]->(o:OU)
RETURN g.name AS GPO, g.domain AS Domain, g.objectid AS GUID,
       o.name AS LinkedOU, o.distinguishedname AS OU_DN
ORDER BY Domain, GPO, LinkedOU"""
        },
        {
            "id": "ous",
            "name": "OU Structure",
            "description": "Organizational unit hierarchy",
            "cypher": """MATCH (o:OU)
RETURN o.name AS OU, o.domain AS Domain, o.distinguishedname AS DN
ORDER BY Domain, OU"""
        },
    ],

    "Kerberos Attacks": [
        {
            "id": "kerberoastable",
            "name": "Kerberoastable Users",
            "description": "Enabled users with SPNs — crack offline with hashcat/john",
            "cypher": """MATCH (u:User)
WHERE u.hasspn = true AND u.enabled = true
RETURN u.name AS User, u.domain AS Domain,
       u.serviceprincipalnames AS SPNs,
       u.pwdlastset AS PwdLastSet,
       u.admincount AS AdminCount
ORDER BY u.admincount DESC, User"""
        },
        {
            "id": "kerberoastable_path_da",
            "name": "Kerberoastable → DA (Shortest Path)",
            "description": "Kerberoastable users with a path to Domain Admins — high-priority targets",
            "cypher": """MATCH p=shortestPath((u:User)-[*1..]->(g:Group))
WHERE u.hasspn = true AND u.enabled = true
  AND g.name =~ '(?i)domain admins@.*'
RETURN u.name AS User, u.domain AS Domain,
       u.serviceprincipalnames AS SPNs, length(p) AS HopsToDA
ORDER BY HopsToDA, User"""
        },
        {
            "id": "asreproast",
            "name": "AS-REP Roastable Users",
            "description": "Users with Kerberos pre-auth disabled — no creds needed to grab hash",
            "cypher": """MATCH (u:User)
WHERE u.dontreqpreauth = true AND u.enabled = true
RETURN u.name AS User, u.domain AS Domain,
       u.pwdlastset AS PwdLastSet,
       u.admincount AS AdminCount
ORDER BY u.admincount DESC, User"""
        },
        {
            "id": "unconstrained_computers",
            "name": "Unconstrained Delegation (Computers)",
            "description": "Non-DC computers with unconstrained delegation — Printer Bug / SpoolSample bait",
            "cypher": """MATCH (c:Computer)
WHERE c.unconstraineddelegation = true AND c.enabled = true
AND NOT EXISTS {
  MATCH (c)-[:MemberOf*1..]->(:Group)
  WHERE toLower(toString(c.name)) CONTAINS 'dc'
}
RETURN c.name AS Computer, c.domain AS Domain,
       c.operatingsystem AS OS, c.dnshostname AS DNS
ORDER BY Domain, Computer"""
        },
        {
            "id": "unconstrained_users",
            "name": "Unconstrained Delegation (Users)",
            "description": "Service accounts with unconstrained delegation — rare and highly dangerous",
            "cypher": """MATCH (u:User)
WHERE u.unconstraineddelegation = true AND u.enabled = true
RETURN u.name AS User, u.domain AS Domain,
       u.serviceprincipalnames AS SPNs
ORDER BY Domain, User"""
        },
        {
            "id": "constrained_delegation",
            "name": "Constrained Delegation Targets",
            "description": "Principals allowed to delegate to specific services — potential s4u2proxy abuse",
            "cypher": """MATCH (n)
WHERE n.allowedtodelegate IS NOT NULL AND size(n.allowedtodelegate) > 0
RETURN labels(n)[0] AS Type, n.name AS Principal, n.domain AS Domain,
       n.allowedtodelegate AS DelegatesToServices
ORDER BY Type, Domain, Principal"""
        },
        {
            "id": "rbcd",
            "name": "RBCD — AllowedToAct",
            "description": "Objects configured with Resource-Based Constrained Delegation",
            "cypher": """MATCH p=(n)-[:AllowedToAct]->(c:Computer)
RETURN n.name AS DelegatePrincipal, labels(n)[0] AS Type,
       c.name AS TargetComputer, c.domain AS Domain
ORDER BY Domain, TargetComputer"""
        },
        {
            "id": "admin_count_kerberoast",
            "name": "Admin-Count Kerberoastable",
            "description": "Protected accounts (adminCount=1) that are Kerberoastable — jackpot",
            "cypher": """MATCH (u:User)
WHERE u.admincount = true AND u.hasspn = true AND u.enabled = true
RETURN u.name AS User, u.domain AS Domain,
       u.serviceprincipalnames AS SPNs,
       u.pwdlastset AS PwdLastSet
ORDER BY Domain, User"""
        },
    ],

    "ACL Abuse": [
        {
            "id": "dcsync",
            "name": "DCSync Rights",
            "description": "Principals with GetChanges+GetChangesAll on a Domain — instant NTDS dump",
            "cypher": """MATCH (n)-[:DCSync|GetChanges|GetChangesAll]->(d:Domain)
RETURN coalesce(n.name, n.objectid) AS Principal, labels(n)[0] AS Type,
       d.name AS Domain
ORDER BY Domain, Principal"""
        },
        {
            "id": "genericall_users",
            "name": "GenericAll on Users",
            "description": "Full control over user objects — reset pw, shadow creds, SPN add",
            "cypher": """MATCH p=(n)-[:GenericAll]->(u:User)
WHERE u.enabled = true
RETURN coalesce(n.name, n.objectid) AS Controller, labels(n)[0] AS ControllerType,
       u.name AS TargetUser, u.admincount AS IsAdmin
ORDER BY u.admincount DESC, TargetUser"""
        },
        {
            "id": "genericall_computers",
            "name": "GenericAll on Computers",
            "description": "Full control over computer objects — RBCD write, shadow creds",
            "cypher": """MATCH p=(n)-[:GenericAll]->(c:Computer)
WHERE c.enabled = true
RETURN n.name AS Controller, labels(n)[0] AS ControllerType,
       c.name AS TargetComputer, c.domain AS Domain
ORDER BY Domain, TargetComputer"""
        },
        {
            "id": "genericall_groups",
            "name": "GenericAll on Privileged Groups",
            "description": "Full control over high-value groups — add yourself as member",
            "cypher": """MATCH p=(n)-[:GenericAll]->(g:Group)
WHERE g.admincount = true
RETURN n.name AS Controller, labels(n)[0] AS ControllerType,
       g.name AS TargetGroup
ORDER BY TargetGroup, Controller"""
        },
        {
            "id": "addmember_privgroups",
            "name": "AddMember on Privileged Groups",
            "description": "Who can add principals to DA/EA/Backup Ops etc.",
            "cypher": """MATCH p=(n)-[:AddMember|GenericAll|GenericWrite]->(g:Group)
WHERE g.name =~ '(?i)(domain admins|enterprise admins|schema admins|administrators|backup operators|account operators|dnsadmins)@.*'
RETURN coalesce(n.name, n.objectid) AS Controller, labels(n)[0] AS ControllerType, g.name AS Group
ORDER BY Group, Controller"""
        },
        {
            "id": "writedacl_domain",
            "name": "WriteDACL / WriteOwner / Owns on Domain",
            "description": "Principals that can modify domain ACL — path to granting DCSync",
            "cypher": """MATCH p=(n)-[r:WriteDacl|WriteOwner|Owns|GenericAll]->(d:Domain)
RETURN n.name AS Principal, labels(n)[0] AS Type,
       type(r) AS Right, d.name AS Domain
ORDER BY Domain, Principal"""
        },
        {
            "id": "forcechangepassword",
            "name": "ForceChangePassword Rights",
            "description": "Who can force password reset — no current pw needed",
            "cypher": """MATCH p=(n)-[:ForceChangePassword]->(u:User)
WHERE u.enabled = true
RETURN n.name AS Controller, labels(n)[0] AS ControllerType,
       u.name AS TargetUser, u.admincount AS IsAdmin
ORDER BY u.admincount DESC, TargetUser"""
        },
        {
            "id": "shadow_creds",
            "name": "Shadow Credentials Paths",
            "description": "AddKeyCredentialLink / GenericWrite on users/computers — add msDS-KeyCredentialLink",
            "cypher": """MATCH p=(n)-[:AddKeyCredentialLink|GenericWrite|GenericAll]->(t)
WHERE (t:User OR t:Computer) AND t.enabled = true
RETURN n.name AS Controller, labels(n)[0] AS ControllerType,
       t.name AS Target, labels(t)[0] AS TargetType
ORDER BY TargetType, Target"""
        },
        {
            "id": "all_extended_rights",
            "name": "AllExtendedRights",
            "description": "Grants all extended rights including GetChanges+GetChangesAll, ForceChangePw",
            "cypher": """MATCH p=(n)-[:AllExtendedRights]->(t)
RETURN n.name AS Controller, labels(n)[0] AS ControllerType,
       t.name AS Target, labels(t)[0] AS TargetType
ORDER BY TargetType, Target"""
        },
        {
            "id": "write_gpo",
            "name": "Write Access to GPOs",
            "description": "Who can modify GPOs — potential mass lateral movement via computer startup scripts",
            "cypher": """MATCH p=(n)-[:GenericAll|GenericWrite|WriteOwner|WriteDacl]->(g:GPO)
RETURN n.name AS Controller, labels(n)[0] AS ControllerType,
       g.name AS GPO, g.domain AS Domain
ORDER BY Domain, GPO"""
        },
        {
            "id": "laps_readers",
            "name": "LAPS Password Readers",
            "description": "Who can read LAPS managed local admin passwords",
            "cypher": """MATCH p=(n)-[:ReadLAPSPassword]->(c:Computer)
RETURN n.name AS Principal, labels(n)[0] AS Type,
       c.name AS Computer, c.domain AS Domain
ORDER BY Domain, Computer"""
        },
    ],

    "ADCS / Cert Abuse": [
        {
            "id": "esc1_candidates",
            "name": "ESC1 — SAN Enrollable Templates",
            "description": "Templates with client auth EKU where enrollee controls SAN — impersonate any user",
            "cypher": """MATCH (n:Certtemplates)
WHERE n.enrolleesuppliessubject = true
  AND ('1.3.6.1.5.5.7.3.2' IN n.ekus
       OR '1.3.6.1.4.1.311.20.2.2' IN n.ekus
       OR '1.3.6.1.5.2.3.4' IN n.ekus)
RETURN n.name AS Template, n.domain AS Domain, n.ekus AS EKUs,
       n.certificatenameflag AS NameFlag
ORDER BY Domain, Template"""
        },
        {
            "id": "esc4_template_write",
            "name": "ESC4 — Template Write Access",
            "description": "Principals with write rights over certificate templates — modify to create ESC1",
            "cypher": """MATCH p=(n)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(t:Certtemplates)
RETURN coalesce(n.name, n.objectid) AS Principal, labels(n)[0] AS Type, t.name AS Template
ORDER BY Template, Principal"""
        },
        {
            "id": "manage_ca",
            "name": "ManageCA / ManageCertificates Rights",
            "description": "Who has Officer/Manager rights over Certificate Authorities",
            "cypher": """MATCH p=(n)-[:ManageCA|ManageCertificates]->(ca:Enterprisecas)
RETURN coalesce(n.name, n.objectid) AS Principal, labels(n)[0] AS Type,
       coalesce(ca.name, ca.objectid) AS CertAuthority, labels(ca)[0] AS CAType
ORDER BY CertAuthority, Principal"""
        },
        {
            "id": "enroll_rights",
            "name": "Certificate Enrollment Rights",
            "description": "Who has Enroll permissions on certificate templates",
            "cypher": """MATCH p=(n)-[:Enroll]->(t:Certtemplates)
RETURN coalesce(n.name, n.objectid) AS Principal, labels(n)[0] AS Type,
       t.name AS Template, t.domain AS Domain
ORDER BY Domain, Template"""
        },
        {
            "id": "pki_write",
            "name": "PKI Flag Write Access",
            "description": "WritePKIEnrollmentFlag / WritePKINameFlag — ESC6/ESC3 variant indicators",
            "cypher": """MATCH p=(n)-[:WritePKIEnrollmentFlag|WritePKINameFlag]->(t:Certtemplates)
RETURN coalesce(n.name, n.objectid) AS Principal, labels(n)[0] AS Type,
       type(relationships(p)[0]) AS Right, t.name AS Template
ORDER BY Template, Principal"""
        },
    ],

    "Local Admin & Lateral Movement": [
        {
            "id": "local_admin_map",
            "name": "All AdminTo Edges",
            "description": "Complete local admin map — who can admin where",
            "cypher": """MATCH p=(n)-[:AdminTo]->(c:Computer)
WHERE c.enabled = true
RETURN n.name AS Principal, labels(n)[0] AS Type,
       c.name AS Computer, c.domain AS Domain, c.operatingsystem AS OS
ORDER BY Domain, Computer, Principal"""
        },
        {
            "id": "most_admin_rights",
            "name": "Top Local Admins (by count)",
            "description": "Users/groups with the most local admin rights across the environment",
            "cypher": """MATCH (u)-[:AdminTo|MemberOf*1..]->(c:Computer)
WHERE (u:User OR u:Group) AND c.enabled = true
RETURN u.name AS Principal, labels(u)[0] AS Type,
       count(DISTINCT c) AS AdminCount
ORDER BY AdminCount DESC
LIMIT 30"""
        },
        {
            "id": "da_sessions",
            "name": "Active DA Sessions",
            "description": "Computers where Domain Admins have active sessions — harvest their token",
            "cypher": """MATCH (u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.name =~ '(?i)domain admins@.*'
MATCH (u)-[:HasSession]->(c:Computer)
RETURN u.name AS DomainAdmin, c.name AS Computer,
       c.domain AS Domain, c.operatingsystem AS OS
ORDER BY Domain, Computer"""
        },
        {
            "id": "rdp_access",
            "name": "RDP Access Map",
            "description": "All CanRDP edges — lateral movement via Remote Desktop",
            "cypher": """MATCH p=(n)-[:CanRDP]->(c:Computer)
WHERE c.enabled = true
RETURN n.name AS Principal, labels(n)[0] AS Type,
       c.name AS Computer, c.domain AS Domain
ORDER BY Domain, Computer"""
        },
        {
            "id": "psremote_access",
            "name": "PowerShell Remoting (WinRM)",
            "description": "Who can PSRemote to which computers",
            "cypher": """MATCH p=(n)-[:CanPSRemote]->(c:Computer)
WHERE c.enabled = true
RETURN n.name AS Principal, labels(n)[0] AS Type,
       c.name AS Computer, c.domain AS Domain
ORDER BY Domain, Computer"""
        },
        {
            "id": "dcom_access",
            "name": "DCOM Access",
            "description": "ExecuteDCOM edges — lateral movement via DCOM",
            "cypher": """MATCH p=(n)-[:ExecuteDCOM]->(c:Computer)
WHERE c.enabled = true
RETURN n.name AS Principal, labels(n)[0] AS Type,
       c.name AS Computer, c.domain AS Domain
ORDER BY Domain, Computer"""
        },
        {
            "id": "domain_users_local_admin",
            "name": "Domain Users → Local Admin",
            "description": "Computers where the Domain Users group has local admin — everyone is admin",
            "cypher": """MATCH p=(g:Group)-[:AdminTo]->(c:Computer)
WHERE g.name =~ '(?i)domain users@.*' AND c.enabled = true
RETURN c.name AS Computer, c.domain AS Domain,
       c.operatingsystem AS OS
ORDER BY Domain, Computer"""
        },
        {
            "id": "sqladmin",
            "name": "SQL Admin Rights",
            "description": "Principals with SQLAdmin access to computers running SQL Server",
            "cypher": """MATCH p=(n)-[:SQLAdmin]->(c:Computer)
RETURN n.name AS Principal, labels(n)[0] AS Type,
       c.name AS SQLServer, c.domain AS Domain
ORDER BY Domain, SQLServer"""
        },
    ],

    "Attack Paths": [
        {
            "id": "owned_objects",
            "name": "Owned Objects",
            "description": "All nodes marked as owned in this engagement",
            "cypher": """MATCH (n)
WHERE n.owned = true
RETURN labels(n)[0] AS Type, n.name AS Name, n.domain AS Domain
ORDER BY Type, Domain, Name"""
        },
        {
            "id": "path_owned_to_da",
            "name": "Owned → Domain Admin (Shortest)",
            "description": "Shortest paths from owned objects to DA — your attack chain",
            "cypher": """MATCH p=shortestPath((o)-[*1..10]->(g:Group))
WHERE o.owned = true AND g.name =~ '(?i)domain admins@.*'
RETURN o.name AS OwnedNode, labels(o)[0] AS Type,
       g.domain AS TargetDomain, length(p) AS Hops
ORDER BY Hops, OwnedNode
LIMIT 50"""
        },
        {
            "id": "path_to_hvt",
            "name": "Any → High Value Target (Shortest)",
            "description": "Shortest paths to all high-value targets from any non-HVT node",
            "cypher": """MATCH p=shortestPath((n)-[*1..8]->(hvt))
WHERE hvt.highvalue = true AND n <> hvt AND NOT n.highvalue = true
  AND NOT n:Domain
RETURN n.name AS Source, labels(n)[0] AS SrcType,
       hvt.name AS HVT, labels(hvt)[0] AS HVTType, length(p) AS Hops
ORDER BY Hops, HVT
LIMIT 50"""
        },
        {
            "id": "cross_domain_paths",
            "name": "Cross-Domain Attack Paths",
            "description": "Nodes in one domain with paths to DA in another — cross-forest pivots",
            "cypher": """MATCH p=shortestPath((n)-[*1..8]->(g:Group))
WHERE g.name =~ '(?i)domain admins@.*'
  AND n.domain IS NOT NULL AND n.domain <> g.domain
RETURN n.name AS Source, n.domain AS SourceDomain,
       g.domain AS TargetDomain, length(p) AS Hops
ORDER BY Hops, SourceDomain
LIMIT 25"""
        },
        {
            "id": "foreign_group_members",
            "name": "Foreign Group Members",
            "description": "Users from one domain that are members of groups in another domain",
            "cypher": """MATCH (u:User)-[:MemberOf]->(g:Group)
WHERE u.domain <> g.domain
RETURN u.name AS User, u.domain AS UserDomain,
       g.name AS Group, g.domain AS GroupDomain
ORDER BY UserDomain, GroupDomain"""
        },
        {
            "id": "sid_history_abuse",
            "name": "SID History Entries",
            "description": "Users with SIDHistory — can impersonate other domain principals",
            "cypher": """MATCH p=(u)-[:HasSIDHistory]->(n)
RETURN u.name AS Principal, labels(u)[0] AS Type,
       n.name AS HistorySID, labels(n)[0] AS SIDType
ORDER BY Type, Principal"""
        },
    ],

    "Quick Stats": [
        {
            "id": "env_overview",
            "name": "Environment Overview",
            "description": "High-level object counts — understand the scope",
            "cypher": """MATCH (n)
WHERE labels(n)[0] IS NOT NULL
RETURN labels(n)[0] AS ObjectType, count(n) AS Count
ORDER BY Count DESC"""
        },
        {
            "id": "pwd_never_expires",
            "name": "Passwords Never Expire",
            "description": "Enabled accounts with non-expiring passwords — stale creds goldmine",
            "cypher": """MATCH (u:User)
WHERE u.pwdneverexpires = true AND u.enabled = true
  AND NOT u.name =~ '.*\\$@.*'
RETURN u.name AS User, u.domain AS Domain,
       u.admincount AS IsAdmin,
       u.pwdlastset AS PwdLastSet
ORDER BY u.admincount DESC, User"""
        },
        {
            "id": "stale_accounts",
            "name": "Stale Accounts (90+ days no logon)",
            "description": "Enabled users with no recent logon — potential zombie accounts to abuse",
            "cypher": """MATCH (u:User)
WHERE u.enabled = true AND u.lastlogon > 0
  AND u.lastlogon < (timestamp()/1000 - 7776000)
  AND NOT u.name =~ '.*\\$@.*'
RETURN u.name AS User, u.domain AS Domain,
       u.lastlogon AS LastLogon
ORDER BY LastLogon ASC
LIMIT 50"""
        },
        {
            "id": "all_computers_os",
            "name": "Computers by OS",
            "description": "OS distribution — spot legacy targets (Server 2008, XP, etc.)",
            "cypher": """MATCH (c:Computer)
WHERE c.enabled = true
RETURN c.operatingsystem AS OS, count(c) AS Count
ORDER BY Count DESC"""
        },
        {
            "id": "owned_percentage",
            "name": "Compromise Completeness",
            "description": "What percentage of users/computers are owned",
            "cypher": """MATCH (n)
WHERE n:User OR n:Computer
WITH labels(n)[0] AS Type, count(n) AS Total,
     sum(CASE WHEN n.owned = true THEN 1 ELSE 0 END) AS Owned
RETURN Type, Total, Owned,
       round(100.0 * Owned / Total, 1) AS PctOwned
ORDER BY Type"""
        },
        {
            "id": "password_not_required",
            "name": "Accounts with No Password Required",
            "description": "Users with PASSWD_NOTREQD flag set",
            "cypher": """MATCH (u:User)
WHERE u.passwordnotreqd = true AND u.enabled = true
RETURN u.name AS User, u.domain AS Domain,
       u.admincount AS IsAdmin,
       u.lastlogon AS LastLogon
ORDER BY u.admincount DESC, User"""
        },
        {
            "id": "description_field",
            "name": "Passwords in Description Fields",
            "description": "Objects with non-empty description — sometimes contains plaintext creds",
            "cypher": """MATCH (n)
WHERE n.description IS NOT NULL
  AND n.description <> ''
  AND (n:User OR n:Computer OR n:Group)
RETURN labels(n)[0] AS Type, n.name AS Name,
       n.domain AS Domain, n.description AS Description
ORDER BY Type, Name
LIMIT 100"""
        },
    ],
}
