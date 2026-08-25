# Plerion — credential setup

[← back to collector docs](../collectors/plerion.md)

Plerion API keys inherit whatever permissions the account/role that
generated them has — there is no independently-scoped, read-only API-client
concept the way Snyk/AppOmni/UpGuard have. The read-only shape here is:
provision a dedicated tenant user with the least-privileged role available,
then generate that user's API key.

## Provision a dedicated read-only user

* As a Plerion tenant administrator, invite a new user (**Settings** >
  **Users** > **Invite**), or use a service account if your identity
  provider supports one. Name it consistently, e.g. `CCM - Read Only`, so
  it's recognisable in audit logs.
* Assign it the most restrictive role Plerion offers that can still view
  findings, assets, and vulnerabilities (a read-only/viewer role). Do not
  grant it an administrator role.

## Generate the API key

* Log in as the read-only user.
* Go to **Settings** > **API Keys** (`https://app.plerion.com/settings/api-keys`).
* Click **Create API Key**, name it (e.g. `ccm-read-only`), and copy the key
  immediately.

## Find your regional endpoint

* Plerion's API is regional: `https://<region>.api.plerion.com` (e.g.
  `au.api.plerion.com`). The region matches the one shown in your tenant's
  Plerion console URL/settings.

## Record the credentials

| Value | Config key | Environment variable |
| --- | --- | --- |
| Regional API host | `endpoint` | `PLERION_ENDPOINT` |
| API key | `api_key` | `PLERION_API_KEY` |
