# Nullify — credential setup

[← back to collector docs](../collectors/nullify.md)

These steps create a dedicated, read-only service-account token for the CCM
integration, per Nullify's own documented flow
(`docs.nullify.ai/api-reference/api-reference/authentication`).

## Create the service account

* Log in to your Nullify tenant dashboard at `https://app.<TENANT>.nullify.ai`
  (`<TENANT>` is your tenant slug).
* Go to **Configure** > **Service Accounts**.
* Select **Create Service Account**, name it `CCM - Read Only`.
* Copy the token value immediately — Nullify only shows it once in the UI.

Nullify's own docs don't call out a read-only/scoped role for service
accounts distinct from a full admin account — if your tenant's role model
offers one, provision it before generating the token; otherwise the token
inherits whatever access the generating account has.

## Find your GitHub owner id and tenant name

* The API base URL is tenant-specific: `https://api.<TENANT>.nullify.ai`,
  using the same `<TENANT>` slug as the dashboard URL above.
* Every API call is also scoped by `githubOwnerId` — the numeric id of the
  GitHub organisation connected to Nullify. Find it under **Configure** >
  **Integrations** > **GitHub**, or from the GitHub organisation's own
  settings (`https://github.com/organizations/<org>/settings/profile` shows
  the org id in the page's account/API details).

## Record the credentials

Store the following values securely — they map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Service Account Token | `token` | `NULLIFY_TOKEN` |
| Tenant API base URL (`https://api.<TENANT>.nullify.ai`) | `endpoint` | `NULLIFY_ENDPOINT` |
| GitHub Owner Id | `github_owner_id` | `NULLIFY_GITHUB_OWNER_ID` |
