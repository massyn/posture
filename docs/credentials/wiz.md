# Wiz — credential setup

[← back to collector docs](../collectors/wiz.md)

These steps create a dedicated Wiz Service Account scoped to read-only API
permissions for the CCM integration. Creating a service account requires
Project Admin (or equivalent) access in Wiz; the account itself only needs
read scopes.

## Create the service account

* Log in to the Wiz console as a user with Project Admin (or higher)
  access.
* Navigate to **Settings** > **Access Management** > **Service Accounts**.
* Select **Add Service Account**.
* Name it `CCM - Read Only`.
* Set **Type** to **Custom Integration (GraphQL API)**.
* Under **API Scopes**, grant only:
    * `read:issues` — `cloud_security_issues`
    * `read:resources` (or `read:inventory`, depending on your Wiz
      tenant's current scope naming) — `inventory`
    * `read:vulnerabilities` — `vulnerabilities`
* Save. Wiz displays the **Client ID** and **Client Secret** once — copy
  both immediately; if you navigate away before saving the secret, you
  must delete and recreate the service account to get a new one.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Client ID | `client_id` | `WIZ_CLIENT_ID` |
| Client Secret | `client_secret` | `WIZ_CLIENT_SECRET` |
| Tenant GraphQL API endpoint (tenant/region-specific, shown in Wiz's API docs page for your tenant) | `api_endpoint` | `WIZ_API_ENDPOINT` |

`token_url` (`WIZ_TOKEN_URL`) is optional — only set it if your tenant is
provisioned on Cognito rather than Wiz's default shared Auth0 endpoint
(Wiz's own console/docs for your tenant will indicate which).

**Caveat:** Wiz's exact scope names for reading cloud inventory
(`read:resources` vs. `read:inventory`) vary by source and Wiz product
version — confirm the current option list shown in your own tenant's
Service Account creation screen before assuming the exact string above.
