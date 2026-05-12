# JACK HOUND — BloodHound Query Engine

Red teamer's self-hosted BloodHound query platform. Drop SharpHound ZIPs, get instant attack path analysis with a cyberpunk terminal UI.

## Stack

- **Neo4j 5.x** — graph database
- **Python / Flask** — API + importer
- **Vanilla JS SPA** — zero build step

## Quick Start

```bash
git clone https://github.com/FlakoJohnson/hound
cd hound
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

## Query Library (54 premade queries)

| Category | Queries | Description |
|---|---|---|
| Domain Recon | 9 | DAs, DCs, trusts, GPOs, high-value targets |
| Kerberos Attacks | 8 | Kerberoast, AS-REP, unconstrained/constrained delegation, RBCD |
| ACL Abuse | 11 | DCSync, GenericAll, WriteDACL, ForceChangePw, shadow creds, LAPS |
| ADCS / Cert Abuse | 5 | ESC1, ESC4, ManageCA, enrollment rights, PKI flag write |
| Local Admin & Lateral Movement | 8 | AdminTo, RDP, PSRemote, DCOM, DA sessions, SQL admin |
| Attack Paths | 6 | Owned→DA, HVT paths, cross-domain, SID history |
| Quick Stats | 7 | Env overview, stale accounts, pwd policies, OS distribution |

## Features

- **Click any row** — opens a details panel with full object properties, group memberships, and notes
- **Right-click any row** — context menu: mark owned, mark high value, copy name/SID/JSON
- **Notes** — per-object freetext notes stored in Neo4j, persist across sessions
- **⌘+Enter** — execute query
- **Filter** — live filter on results table
- **↓ CSV / ⎘ MARKDOWN / ⎘ COPY TABLE** — export results
- **Custom Query** — full Cypher editor tab
- **⚡ CLEAR DB** — wipe and reimport for new engagements

## Marking Owned Objects

Right-click any row → **⚑ Mark as Owned** or **★ Mark High Value**.

Or via the Custom Query tab:
```cypher
MATCH (u:User {name: "JDOE@DOMAIN.COM"}) SET u.owned = true
MATCH (c:Computer {name: "WS01.DOMAIN.COM"}) SET c.owned = true
```
Then run **Owned → Domain Admin (Shortest)** from the Attack Paths category.

## Authentication

Set `HOUND_TOKEN` in the environment to require a token on all API calls:

```bash
HOUND_TOKEN=mysecrettoken docker compose up -d --build
```

The UI will prompt for the token on first load and store it in session storage.

## Change Neo4j Password

Edit `docker-compose.yml` → set `NEO4J_PASS` under the hound service environment, and update `NEO4J_AUTH` under the neo4j service to match.

## Resource Requirements

- RAM: 2GB minimum (4GB recommended for large engagements)
- Disk: Neo4j stores ~500MB per 100k nodes typical
