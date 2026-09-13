# Backlog

Collectors and capabilities that have been scoped but deliberately deferred,
with the reason. Not a wishlist — each entry is something a decision was
already taken on.

## AWS Security Hub

**Deferred:** credential model.

The other collectors take an explicit secret set (API key, client
id/secret, service-account JSON) resolved from config or env vars. AWS
production access frequently is *not* a static access key / secret key pair
— workloads run with instance-profile / IRSA / SSO role credentials that the
AWS SDK resolves from the environment (metadata endpoint, `~/.aws/config`,
`AWS_*` vars, web-identity token file) via its default credential provider
chain. A first cut that only accepts `aws_access_key_id` /
`aws_secret_access_key` would not fit how posture is actually run in AWS.

Before building this:

- Decide whether the collector shells out to `boto3`'s default provider
  chain (accepting an optional explicit key pair as an override) or stays
  key-pair-only. `boto3` would be a new optional dependency (`posture[aws]`),
  in the same tier as `pytenable` / `simple-salesforce`.
- Region handling: Security Hub is regional; a full posture snapshot spans
  every enabled region, so the collector needs to enumerate regions or take
  a region list.
- Scope: `findings` (`GetFindings`, paginated, ASFF schema), `standards` /
  `standards_controls` (`DescribeStandards` / `DescribeStandardsControls`),
  `insights`. ASFF findings are deeply nested — the manifest will be large.

## GCP Security Command Center — extra surface

The `gcp_security_command_center` collector ships with `findings`,
`sources`, and (legacy) `assets`. Still worth adding once verified against a
real org:

- `mute_configs`, `notification_configs`, `big_query_exports` — config
  posture of SCC itself.
- The newer `securitycenter.googleapis.com/v2` resource API (org/folder/
  project-scoped) in place of the deprecated v1 `assets` inventory.

## Secureframe

**Deferred:** API shape unverified.

Secureframe exposes a GraphQL API (`developer.secureframe.com`), not the
REST-with-cursor shape every other GRC collector here (`vanta`, `drata`)
follows. Modelling the GraphQL queries and response nesting without a real
tenant to introspect against would be guessing at both the query structure
*and* the field paths — a weaker footing than the "field names from public
REST docs" caveat the other collectors carry. Build once there is a tenant
to verify the queries against, following `wiz.py` / `crowdstrike_identity.py`
as the GraphQL reference collectors.
