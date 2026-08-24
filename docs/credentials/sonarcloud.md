# SonarCloud — credential setup

[← back to collector docs](../collectors/sonarcloud.md)

SonarCloud tokens inherit whatever permissions the account that generated
them has in the organization — there is no separate, independently-scoped
API-client concept the way Snyk/AppOmni/UpGuard have. The read-only shape
here is: provision a dedicated user, give it the least-privileged role that
still exposes the resources this collector reads (`organizations`,
`projects`, `issues`, `hotspots`, `quality_gate_status`, `measures`), then
generate that user's token.

## Provision a dedicated read-only member

* As an organization administrator, invite a new member to the
  organization (**Organization** > **Members** > **Invite**), or use a
  service/bot account if your identity provider supports one.
* Name it consistently, e.g. `CCM - Read Only`, so it's recognisable in
  audit logs.
* Do **not** grant it the **Admin** organization permission, and do not add
  it to any group with **Administer**, **Administer Security Hotspots**,
  or **Execute Analysis** permissions. Membership alone is enough to read
  project/issue/hotspot/quality-gate/measure data for every project the
  member has **Browse** access to — SonarCloud's default is that every
  organization member can browse every public project without any extra
  grant. If your organization uses private projects, either add the
  read-only member to a group with **Browse** permission on those
  projects, or grant it directly per-project (**Project** > **Permissions**
  > **Browse**).

## Generate the token

* Log in as the read-only member (or, for a bot account, however your
  identity provider surfaces its session).
* Go to **My Account** > **Security**.
* Under **Generate Tokens**, enter a name (e.g. `ccm-read-only`), leave the
  type as a User Token, and select an expiry appropriate for your
  operational process (SonarCloud tokens can be set to never expire, but a
  rotation policy is recommended).
* Click **Generate** and copy the token immediately — SonarCloud shows it
  only once.

## Find the organization key

* The organization key is shown in the URL when browsing the organization
  (`https://sonarcloud.io/organizations/<key>/...`) and on
  **Organization** > **Administration** > **General Settings**.

## Record the credentials

| Value | Config key | Environment variable |
| --- | --- | --- |
| User token | `token` | `SONARCLOUD_TOKEN` |
| Organization key | `organization` | `SONARCLOUD_ORGANIZATION` |
