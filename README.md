# JACK HOUND — BloodHound Query Engine

Red teamer's self-hosted BloodHound query platform. Drop SharpHound ZIPs, get instant attack path analysis with a cyberpunk terminal UI.

## Stack

- **Neo4j 5.x** — graph database
- **Python / Flask** — API + importer
- **Vanilla JS SPA** — zero build step

## Installation

### Requirements

- Docker + Docker Compose
- 2 GB RAM minimum (4 GB recommended for large datasets)

### First Run

```bash
git clone https://github.com/FlakoJohnson/hound
cd hound

# Create the data directory (persists Neo4j data and the user database)
mkdir -p data

# Start with authentication enabled
HOUND_PASS=changeme docker compose up -d --build
```

On first boot, hound bootstraps an `admin` account from `HOUND_USER` (default: `admin`) and `HOUND_PASS`. After that, manage users through the UI — the env var is no longer used for login.

```
App      → http://localhost:8080
Neo4j    → http://localhost:7474  (neo4j / bloodhound)
```

### Without Authentication

```bash
docker compose up -d --build
# No HOUND_PASS = no login required
```

### Persistent Deployment

Set variables in a `.env` file alongside `docker-compose.yml`:

```env
HOUND_PASS=your-admin-password
HOUND_USER=admin
SECRET_KEY=generate-a-random-32-char-string
NEO4J_PASS=bloodhound
```

Then just run:

```bash
docker compose up -d --build
```

`SECRET_KEY` signs Flask session cookies. If unset, a random key is generated at startup — this invalidates all sessions on container restart.

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

## Authentication & User Management

Login is username + password via a session cookie. Open the app and you'll see the login form when auth is enabled.

### Roles

| Role | Run Queries | Upload / Clear / Mark Owned / Notes | Manage Users |
|---|:---:|:---:|:---:|
| `admin`    | ✓ | ✓ | ✓ |
| `operator` | ✓ | ✓ | ✗ |
| `user`     | read-only MATCH only | ✗ | ✗ |

### Managing Users

Log in as `admin` → click **⚙ USERS** in the header. From there you can create accounts, set roles, enable/disable, and delete users.

To create a user via the CLI (while the container is running):

```bash
# Create an operator account
curl -s -c /tmp/h.jar -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"changeme"}'

curl -s -b /tmp/h.jar -X POST http://localhost:8080/api/users \
  -H 'Content-Type: application/json' \
  -d '{"username":"analyst","password":"hunter2","role":"operator"}'
```

### Legacy Token Auth

`HOUND_TOKEN` is still supported for headless API clients (scripts, pipelines). Set it in the environment and pass it via the `X-Hound-Token` header — no session needed.

## Change Neo4j Password

Edit `docker-compose.yml` → set `NEO4J_PASS` under the hound service environment, and update `NEO4J_AUTH` under the neo4j service to match.

## Upgrading

```bash
cd hound
git pull
docker compose up -d --build
```

Data persists in Docker volumes (`neo4j_data`, `neo4j_logs`) and `./data/users.db`. No manual migration needed.

## Resource Requirements

- RAM: 2 GB minimum (4 GB recommended for large engagements)
- Disk: Neo4j stores ~500 MB per 100k nodes typical
