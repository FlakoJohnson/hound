"""Read-only graph queries shared across the app.

Domain scoping and stat counting used to live on BloodHoundImporter, which owned
them only because it was once the single module that touched Neo4j. Now that
exporter.py needs the same domain predicate, keeping one copy here stops the two
from drifting — they already had subtly different Domain-node handling.
"""

import logging

logger = logging.getLogger(__name__)

# Domain-scope predicate for a node bound as `n`, parameterised on $domain.
#
# Domain nodes are matched on `name` as well as `domain`: some collectors leave
# the `domain` property unset on the domain object itself, which would drop that
# node (and, in an export, all of its ACEs) while every other object came
# through — a silent, hard-to-spot hole rather than an obvious failure.
DOMAIN_SCOPE = '(n.domain = $domain OR (n:Domain AND n.name = $domain))'

# AD object labels. `name IS NOT NULL` keeps the chip counts consistent with the
# list views, which already filter out namespaced BUILTIN stubs and other
# name-less nodes created as ACE reference targets.
AD_OBJECT_LABELS = ['User', 'Computer', 'Group', 'Domain', 'GPO', 'OU', 'Container']

# AD CS labels are only created from their own JSON files, never stubbed from an
# ACE reference, so they need no name filter.
ADCS_LABELS = ['CertTemplate', 'EnterpriseCA', 'RootCA', 'AIACA',
               'NTAuthStore', 'IssuancePolicy']


def get_stats(driver, domain=None):
    """Node and relationship counts, optionally scoped to a single domain."""
    stats = {}
    params = {'domain': domain} if domain else {}

    with driver.session() as session:
        for lbl in AD_OBJECT_LABELS:
            where = ('WHERE n.name IS NOT NULL AND ' + DOMAIN_SCOPE
                     if domain else 'WHERE n.name IS NOT NULL')
            try:
                r = session.run(
                    f"MATCH (n:{lbl}) {where} RETURN count(n) AS c",
                    **params).single()
                stats[lbl] = r['c'] if r else 0
            except Exception:
                logger.exception('stats failed for label %s', lbl)
                stats[lbl] = 0

        for lbl in ADCS_LABELS:
            where = f'WHERE {DOMAIN_SCOPE}' if domain else ''
            try:
                r = session.run(
                    f"MATCH (n:{lbl}) {where} RETURN count(n) AS c",
                    **params).single()
                stats[lbl] = r['c'] if r else 0
            except Exception:
                logger.exception('stats failed for label %s', lbl)
                stats[lbl] = 0

        try:
            if domain:
                # A relationship is in scope if either end is in the domain, so
                # cross-domain edges stay visible from both sides instead of
                # vanishing from both. Per-domain totals can therefore sum to
                # more than the graph-wide total once trusts exist.
                q = ("MATCH (a)-[r]->(b) "
                     "WHERE a.domain = $domain OR b.domain = $domain "
                     "RETURN count(r) AS c")
            else:
                q = "MATCH ()-[r]->() RETURN count(r) AS c"
            r = session.run(q, **params).single()
            stats['Relationships'] = r['c'] if r else 0
        except Exception:
            logger.exception('relationship count failed')
            stats['Relationships'] = 0

    return stats
