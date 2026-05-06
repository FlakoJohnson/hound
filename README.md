# 🐕 HOUND — BloodHound Query Engine

Red teamer's self-hosted BH query platform. Drop SharpHound ZIPs, get instant attack path analysis.

## Stack
- **Neo4j 5.x** — graph database
- **Python / Flask** — API + importer
- **Vanilla JS SPA** — cyberpunk terminal UI, zero build step

## Quick Start

```bash
git clone <this-repo> && cd bh-query-engine
docker compose up -d --build
# App → http://localhost:8080
# Neo4j browser → http://localhost:7474 (neo4j / bloodhound)
```

## Import Data

1. Open http://localhost:8080
2. Click **⬆ IMPORT** tab
3. Drop your SharpHound `.zip` or individual `.json` files
4. Stats update automatically in the header

### Supported Formats
- SharpHound v4 / v5 (BloodHound CE)
- ZIP archives (mixed JSON files)
- Individual JSON files (users.json, computers.json, etc.)

## Query Library (50+ premade queries)

| Category | # Queries | Description |
|---|---|---|
| Domain Recon | 8 | DAs, DCs, trusts, GPOs, high-value targets |
| Kerberos Attacks | 7 | Kerberoast, AS-REP, unconstrained/constrained delegation, RBCD |
| ACL Abuse | 10 | DCSync, GenericAll, WriteDACL, ForceChangePw, shadow creds, LAPS |
| ADCS / Cert Abuse | 5 | ESC1, ESC4, ManageCA, enrollment rights, PKI flag write |
| Local Admin & Lateral | 8 | AdminTo, RDP, PSRemote, DCOM, DA sessions, SQL admin |
| Attack Paths | 6 | Owned→DA, HVT paths, cross-domain, SID history |
| Quick Stats | 7 | Env overview, stale accounts, pwd policies, OS distribution |

## Features

- **⌘+Enter** — execute query (keyboard shortcut)
- **Filter** — live regex-free filter on results table
- **↓ CSV** — export any result set to CSV
- **⎘ COPY TABLE** — tab-separated for spreadsheet paste
- **Custom Query** — full Cypher editor tab
- **CLEAR DB** — wipe and reimport for new engagements

## Custom Cypher

Use the **CUSTOM QUERY** tab for ad-hoc Cypher. Full Neo4j support, results render in the same table UI.

## Marking Owned Objects

In Neo4j (port 7474) or via custom query:
```cypher
MATCH (u:User {name: "JDOE@DOMAIN.COM"}) SET u.owned = true
MATCH (c:Computer {name: "WS01.DOMAIN.COM"}) SET c.owned = true
```
Then use **Owned → Domain Admin (Shortest)** query.

## Change Neo4j Password

Edit `docker-compose.yml` → `NEO4J_AUTH=neo4j/<newpassword>` and update `NEO4J_PASS` in hound service.

## Resource Requirements
- RAM: 2GB minimum (4GB recommended for large engagements)
- Disk: depends on dataset size (Neo4j stores ~500MB per 100k nodes typical)
