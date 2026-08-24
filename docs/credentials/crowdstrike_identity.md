# CrowdStrike Falcon Identity Protection — credential setup

[← back to collector docs](../collectors/crowdstrike_identity.md)

Falcon Identity Protection (formerly Preempt) is a distinct product surface
from Falcon endpoint protection ([CrowdStrike](crowdstrike.md)) and Falcon
Cloud Security ([CrowdStrike CSPM](crowdstrike_cspm.md)) — it needs its own
dedicated API client, even against the same Falcon tenant.

## Create the API client

* Sign in to your CrowdStrike Falcon instance as an administrator.
* Expand the side menu and select **Support and resources**.
* Under **Resources and tools**, select **API clients and keys**.
* Select **Create API client** (or **Add new API client**, depending on
  your Falcon console version).
* Fill in the following fields:
    * **Client Name**: `CCM - Read Only`
    * **Description**: `CrowdStrike Identity Protection API Read-Only key for CCM`
* Under **Scope**, enable **Read** for:
    * **Identity Protection Entities** — covers `entities`/
      `entity_risk_factors` (the GraphQL inventory/risk-factor resources)
    * **Alerts** — covers `detections` (identity-related alerts, pulled via
      the shared Falcon Alerts API v2, filtered to `product:'idp'`)
* Select **Create**.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Client ID | `client_id` | `CROWDSTRIKE_IDENTITY_CLIENT_ID` |
| Client Secret | `client_secret` | `CROWDSTRIKE_IDENTITY_CLIENT_SECRET` |

The collector auto-discovers your CrowdStrike cloud region from the token
response, the same as [CrowdStrike](crowdstrike.md) and
[CrowdStrike CSPM](crowdstrike_cspm.md) — no base URL to configure.
