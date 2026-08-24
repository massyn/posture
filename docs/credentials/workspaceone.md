# Workspace ONE — credential setup

[← back to collector docs](../collectors/workspaceone.md)

These steps create a dedicated OAuth client for the CCM integration.
Workspace ONE UEM's OAuth clients are supported in SaaS environments only
(not on-prem) and are bound to a role and Organization Group at creation
time — pick the narrowest read-only role your console offers rather than a
full administrator role.

## Create a read-only role (if one doesn't already exist)

* Log in to the Workspace ONE UEM console as an administrator.
* Navigate to **Accounts** > **Administrators** > **Roles**.
* If your environment doesn't already have a read-only role, create one
  (e.g. `CCM - Read Only`) granting **View** access to **Devices** and
  related device-inventory resources only — no **Manage**/**Edit**/
  **Delete** permissions.

## Create the OAuth client

* Navigate to **Groups & Settings** > **Configurations**.
* Search for `OAuth` and select **OAuth Client Management**.
* Select **Add**.
* Fill in:
    * **Name**: `CCM - Read Only`
    * **Description**: a short note on what this integration is for
    * **Organization Group**: the OG scoping which devices this client can
      see
    * **Role**: the read-only role created above
* Save. Workspace ONE displays the **Client ID** and **Client Secret**
  once — copy both immediately; the secret cannot be retrieved again.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Client ID | `client_id` | `WORKSPACEONE_CLIENT_ID` |
| Client Secret | `client_secret` | `WORKSPACEONE_CLIENT_SECRET` |
| API server host (your tenant's REST API URL, e.g. `https://asXXX.awmdm.com`) | `api_server` | `WORKSPACEONE_API_SERVER` |

`token_url` (`WORKSPACEONE_TOKEN_URL`) is optional — it defaults to the
APAC OAuth token endpoint (`https://apac.uemauth.workspaceone.com/connect/token`).
**If your tenant isn't hosted in APAC, you must set this explicitly** to
your region's token endpoint (Workspace ONE has separate `na`/`emea`/`apac`
OAuth hosts and provides no documented way to derive the correct one from
`api_server` alone) — check your console's API documentation page for the
exact regional token URL.
