#!/usr/bin/env python3
"""Execute every query in the library against a live graph and report health.

Not a pass/fail test — an empty result is often correct (the environment simply
has no ESC1 templates). The useful signal is separating those from queries that
error, and from queries that return nothing because they reference a property or
label the graph never populates. That last class fails silently and is exactly
how the highvalue and DCSync bugs went unnoticed.

    python tests/run_all_queries.py
"""

import os
import re
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from neo4j import GraphDatabase          # noqa: E402
from queries import QUERIES              # noqa: E402

# Properties and labels a query might filter on that the importer may never set.
# An empty result from a query touching one of these is suspicious rather than
# merely uneventful, so it gets called out separately.
SUSPECT_TOKENS = [
    'highvalue', 'system_tags', 'Tag_Tier_Zero', 'owned', 'isacl',
    'admincount', 'isdc', 'unconstraineddelegation', 'sidhistory',
    'gmsa', 'laps', 'haslaps', 'trustedtoauth', 'dontreqpreauth', 'hasspn',
]


def graph_inventory(session):
    """What the graph actually contains, to judge empty results against."""
    inv = {}
    for lbl in ['User', 'Computer', 'Group', 'Domain', 'GPO', 'OU', 'Container',
                'CertTemplate', 'EnterpriseCA']:
        inv[lbl] = session.run(
            f'MATCH (n:{lbl}) RETURN count(n) AS c').single()['c']
    for prop in SUSPECT_TOKENS:
        try:
            inv[f'prop:{prop}'] = session.run(
                f'MATCH (n) WHERE n.`{prop}` IS NOT NULL '
                'RETURN count(n) AS c').single()['c']
        except Exception:
            inv[f'prop:{prop}'] = -1
    return inv


def main():
    driver = GraphDatabase.driver(
        os.environ.get('NEO4J_URI', 'bolt://localhost:7687'),
        auth=(os.environ.get('NEO4J_USER', 'neo4j'),
              os.environ.get('NEO4J_PASS', 'bloodhound')))
    driver.verify_connectivity()

    with driver.session() as s:
        inv = graph_inventory(s)

    print('GRAPH: ' + '  '.join(
        f'{k}={v}' for k, v in inv.items() if not k.startswith('prop:') and v))
    missing = [k.split(':', 1)[1] for k, v in inv.items()
               if k.startswith('prop:') and v == 0]
    if missing:
        print(f'PROPERTIES NEVER SET: {", ".join(missing)}')
    print()

    errored, empty, suspect, ok = [], [], [], []

    for cat, items in QUERIES.items():
        for q in items:
            cypher = q['cypher']
            started = time.time()
            try:
                with driver.session() as s:
                    rows = list(s.run(cypher))
                elapsed = time.time() - started
            except Exception as e:
                errored.append((cat, q['id'], str(e).split('\n')[0][:120]))
                continue

            n = len(rows)
            if n:
                ok.append((cat, q['id'], n, elapsed))
                continue

            # Empty. Does it lean on something the graph never populates?
            tokens = [t for t in SUSPECT_TOKENS
                      if re.search(rf'\b{re.escape(t)}\b', cypher)
                      and inv.get(f'prop:{t}', -1) == 0]
            if tokens:
                suspect.append((cat, q['id'], tokens))
            else:
                empty.append((cat, q['id']))

    print(f'== ERRORED ({len(errored)}) ==')
    for cat, qid, err in errored:
        print(f'  [{cat}] {qid}: {err}')

    print(f'\n== EMPTY, references never-populated property ({len(suspect)}) ==')
    for cat, qid, toks in suspect:
        print(f'  [{cat}] {qid}: {", ".join(toks)}')

    print(f'\n== EMPTY, plausibly just absent in this data ({len(empty)}) ==')
    for cat, qid in empty:
        print(f'  [{cat}] {qid}')

    print(f'\n== RETURNED ROWS ({len(ok)}) ==')
    for cat, qid, n, el in sorted(ok, key=lambda x: -x[3])[:12]:
        print(f'  [{cat}] {qid}: {n} rows, {el:.2f}s')
    if len(ok) > 12:
        print(f'  … and {len(ok) - 12} more')

    total = len(errored) + len(suspect) + len(empty) + len(ok)
    print(f'\nTOTAL {total} | rows {len(ok)} | empty {len(empty)} '
          f'| suspect {len(suspect)} | errored {len(errored)}')
    driver.close()
    return 1 if errored else 0


if __name__ == '__main__':
    sys.exit(main())
