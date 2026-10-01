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
  on Asset Management, Issues and Vulnerability Management (the three
  areas this collector reads). The `vulnerabilities` resource also needs
  a Cortex Cloud Runtime Security or Posture Management licence.
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
| *(Optional)* Per-read timeout in seconds for the `vulnerabilities` snapshot stream (default `600`) | `snapshot_timeout` | `CORTEX_SNAPSHOT_TIMEOUT` |

**`vulnerabilities` quota:** the snapshot export behind this resource is
limited by Cortex to **10 requests per rolling 24 hours**. The
collector never retries it automatically, so a failed run costs one
request. Avoid scheduling more than a few full pulls a day, and run
smoke tests with `record_limit`, which caps the server-side `limit`.

**Caveat:** exact built-in role names (e.g. whether "Viewer" exists
out-of-the-box vs. requiring a custom role) vary by Cortex tenant
configuration — confirm the closest available read-only role against your
own tenant's **Settings** > **Access Management** > **Roles** before
assuming a specific name.
