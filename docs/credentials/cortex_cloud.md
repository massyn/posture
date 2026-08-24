# Palo Alto Cortex Cloud — credential setup

[← back to collector docs](../collectors/cortex_cloud.md)

These steps create a **Standard** API key with a read-only role for the CCM
integration. Cortex Cloud shares its API platform with Cortex XDR/XSIAM,
so key management lives under the same **Settings** area regardless of
which Cortex product you're licensed for.

## Create the API key

* Log in to your Cortex Cloud/XSIAM tenant as an administrator.
* Navigate to **Settings** > **Configurations** > **Integrations** >
  **API Keys**.
* Select **New Key**.
* Set the **Security Level** to **Standard** (this collector uses the
  Standard header-based auth mode — `Authorization`/`x-xdr-auth-id` — not
  Advanced's nonce/timestamp/hash scheme).
* Under **Role**, select a read-only role — either a built-in **Viewer**
  role if your tenant has one, or a custom role scoped to read-only access
  on Asset Management and Issues (the two resources this collector reads).
* Name the key `CCM - Read Only` and generate it.
* Copy the **API Key** value immediately — it is only shown once.
* Note the **API Key ID** shown alongside it (also available later via
  **Settings** > **Configurations** > **Integrations** > **API Keys**).

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| API Key | `token` | `CORTEX_TOKEN` |
| API Key ID | `api_key_id` | `CORTEX_API_KEY_ID` |
| Tenant API host (the `api-<fqdn>` shown in your tenant's API settings) | `endpoint` | `CORTEX_ENDPOINT` |

**Caveat:** exact built-in role names (e.g. whether "Viewer" exists
out-of-the-box vs. requiring a custom role) vary by Cortex tenant
configuration — confirm the closest available read-only role against your
own tenant's **Settings** > **Access Management** > **Roles** before
assuming a specific name.
