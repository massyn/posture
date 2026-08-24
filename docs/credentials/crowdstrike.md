# CrowdStrike — credential setup

[← back to collector docs](../collectors/crowdstrike.md)

These steps create a dedicated API client with read-only scopes for the CCM
integration.

## Create the API client

* Log in to your CrowdStrike Falcon user interface as an admin-level user.
* Select the Falcon menu, select **Support**, then select **API Clients and Keys**.
* Select **Add new API client**.
* In **CLIENT NAME**, enter `CCM - Read Only`.
* In **DESCRIPTION**, enter `CrowdStrike API Read-Only key for CCM`.
* Set these API scopes to **READ**:
    * Detections
    * Hosts
    * Host Groups
    * Prevention Policies
    * Sensor Update Policies
    * User Management
    * Vulnerabilities
* Select **Add**.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Client ID | `client_id` | `CROWDSTRIKE_CLIENT_ID` |
| Secret | `client_secret` | `CROWDSTRIKE_CLIENT_SECRET` |

The collector auto-discovers your CrowdStrike cloud region (`us-1`/`us-2`/
`eu-1`/`us-gov-1`) from the token response — no base URL to configure.
