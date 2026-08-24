# SailPoint Identity Security Cloud — credential setup

[← back to collector docs](../collectors/sailpoint.md)

This targets Identity Security Cloud (ISC, the cloud SaaS product formerly
IdentityNow) — not self-hosted IdentityIQ, a different product entirely.
These steps create a Personal Access Token (PAT), which is what ISC's REST
API actually authenticates against under the hood; despite the name it
behaves as a client ID/secret pair suitable for a service integration, not
just an interactive user credential. PATs inherit the creating user's
access, so create them under a dedicated service account provisioned with
the minimum admin capability ISC's role model allows (a read-only or
reporting-scoped admin role, if your org has one) rather than a personal
admin account.

## Create the service account

* Log in to Identity Security Cloud as an administrator.
* Provision a dedicated user for the integration (e.g. `ccm-readonly`) via
  **Admin** > **Identities**, or use an existing dedicated service identity
  if your org already provisions those centrally.
* Assign that identity the narrowest admin capability your ISC tenant
  offers for reading identities/accounts/access profiles/roles — check
  **Admin** > **Global** > **Security Settings** > **Global Access Control**
  for the available role/workgroup options in your tenant, since ISC's
  built-in role names vary by deployment.

## Generate the Personal Access Token

* Sign in to ISC **as the service account** (the token inherits the
  creating account's access).
* Select the account/profile menu (top right) > **Preferences**.
* Select **Personal Access Tokens** in the left navigation.
* Select **New Token**, enter a description of `CCM - Read Only`, and
  select **Create Token**.
* Copy the **Client ID** and **Secret** immediately — the secret is only
  shown once.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| ISC tenant base URL (e.g. `https://yourtenant.api.identitynow.com`) | `base_url` | `SAILPOINT_BASE_URL` |
| Client ID | `client_id` | `SAILPOINT_CLIENT_ID` |
| Secret | `client_secret` | `SAILPOINT_CLIENT_SECRET` |

**Caveat:** ISC limits each user to 10 Personal Access Tokens — if the
service account already has tokens for other integrations, delete unused
ones before creating this one. Confirm the exact minimum-privilege
role/workgroup available for the service account against your own tenant's
admin console — ISC's role model isn't uniform across orgs.
