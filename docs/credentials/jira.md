# Jira — credential setup

[← back to collector docs](../collectors/jira.md)

Jira collection supports two deployment types, chosen by `auth_type`
(`JIRA_AUTH_TYPE`, default `cloud`). Pick the section matching your instance.

## Cloud (`auth_type=cloud`, default)

Cloud has no independently-scoped API-client concept for the Table/Search
APIs — a user's API token inherits that user's own permissions. The
read-only shape here is: provision a dedicated user with the minimum
Jira role needed to browse the projects this collector reads, then generate
that user's API token.

### Provision a dedicated read-only user

* As a Jira/Atlassian organization administrator, invite a new user (or use
  a service account if your identity provider supports one). Name it
  consistently, e.g. `CCM - Read Only`, so it's recognisable in audit logs.
* Grant it the **Browse Projects** permission (via a permission scheme or
  project role) for every project this collector should read. Do **not**
  grant **Administer Projects**, **Edit Issues**, or any Jira administrator
  global permission.

### Generate the API token

* Log in as the read-only user.
* Go to **id.atlassian.com** > **Security** > **API tokens** > **Create API
  token**.
* Name it (e.g. `ccm-read-only`), set an expiry appropriate for your
  rotation policy, and copy the token immediately — it is shown only once.

## Server / Data Center (`auth_type=server`)

Self-hosted Jira has no separate API-client concept either; a Personal
Access Token (PAT) inherits the generating user's own permissions, same
shape as Cloud's API token.

### Provision a dedicated read-only user

* As a Jira administrator, create a dedicated user (or service account).
* Grant it **Browse Projects** only, via a permission scheme or project
  role, for the projects this collector should read. Do not grant it any
  Jira administrator global permission.

### Generate the Personal Access Token

* Log in as the read-only user.
* Go to **Profile** > **Personal Access Tokens** > **Create token**.
* Name it, set an expiry, and copy the token immediately.

## Custom fields

`fields.customfield_10001`-style field ids are specific to each Jira
instance and project — there is no universal mapping. See
[`jira.json`](../../src/posture/collectors/jira.json) (or your own
`schema_file`) to declare which custom fields to collect and under what
column name; find each field's id via `GET
<endpoint>/rest/api/{2,3}/field` while logged in as an administrator, or
via **Jira Settings** > **Issues** > **Custom fields**.

## Record the credentials

| Value | Config key | Environment variable | Applies to |
| --- | --- | --- | --- |
| Base URL | `endpoint` | `JIRA_ENDPOINT` | both |
| Deployment type | `auth_type` | `JIRA_AUTH_TYPE` | both (default `cloud`) |
| User email | `email` | `JIRA_EMAIL` | cloud |
| API token | `api_token` | `JIRA_API_TOKEN` | cloud |
| Personal Access Token | `personal_access_token` | `JIRA_PERSONAL_ACCESS_TOKEN` | server |
| Custom field mapping file | `schema_file` | `JIRA_SCHEMA_FILE` | both (optional) |
