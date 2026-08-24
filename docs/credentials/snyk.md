# Snyk — credential setup

[← back to collector docs](../collectors/snyk.md)

These steps create a dedicated Service Account with a read-only custom role
for the CCM integration — Snyk recommends Service Accounts over personal
API tokens for automation, since a Service Account isn't tied to a human
user's own access and survives that person leaving.

## Create a read-only custom role

* Log in to Snyk as an organization/group administrator.
* Navigate to your Organization's **Settings** > **Roles** (or the
  Group-level role manager, if provisioning at Group scope).
* Select **Manage role** / **Create custom role**.
* Name it `CCM - Read Only` and grant only read-level permissions covering
  organizations, projects, issues, and targets — the resources this
  collector reads. Do not grant any write/manage permissions.
* Save the role.

## Create the Service Account

* Navigate to **Settings** > **Service Accounts** (Organization or Group
  level, depending on how broadly the integration needs to see).
* Select **Create Service Account**.
* Name it `CCM - Read Only`.
* Assign the custom read-only role created above (Organization-level
  service accounts only expose Admin/Collaborator as built-in roles — a
  custom role is required to get read-only; a Group-level service account
  can instead use the built-in **Group Viewer** role if you don't need a
  custom one).
* Generate the account's API token/credentials and store them securely.

## Record the credentials

Store the following value securely — it maps directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Service Account token | `token` | `SNYK_TOKEN` |

`endpoint` (`SNYK_ENDPOINT`) is optional — only set it if your organization
is provisioned on a non-default Snyk API region/host.
