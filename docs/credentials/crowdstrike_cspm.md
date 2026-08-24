# CrowdStrike Falcon Cloud Security (CSPM) — credential setup

[← back to collector docs](../collectors/crowdstrike_cspm.md)

These steps create a dedicated API client with read-only CSPM scopes for the
CCM integration. This is a distinct product surface from Falcon endpoint
protection (see [CrowdStrike](crowdstrike.md)) — it needs its own API client
and its own credentials, even against the same Falcon tenant.

## Create the API client

* Sign in to your CrowdStrike Falcon instance as an administrator.
* Expand the side menu and select **Support and resources**.
* Under **Resources and tools**, select **API clients and keys**.
* Select **Create API client**.
* Fill in the following field:
    * **Client Name**: `CCM - Read Only`
* Under **Scope**, enable the following permission to **Read**:
    * CSPM Registration
* Select **Create**.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Client ID | `client_id` | `CROWDSTRIKE_CSPM_CLIENT_ID` |
| Client Secret | `client_secret` | `CROWDSTRIKE_CSPM_CLIENT_SECRET` |

The collector auto-discovers your CrowdStrike cloud region from the token
response, the same as [CrowdStrike](crowdstrike.md) — no base URL to
configure.
