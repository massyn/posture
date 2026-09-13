# GCP Security Command Center — credential setup

[← back to collector docs](../collectors/gcp_security_command_center.md)

These steps create a dedicated service account with the minimum
organization-level role Security Command Center's read APIs need, rather
than reusing a broader project-owner service account.

## Create the service account

* Sign in to the [Google Cloud Console](https://console.cloud.google.com)
  as a user with **Organization Admin** or equivalent IAM-granting
  permissions.
* Navigate to **IAM & Admin** > **Service Accounts** in a project under the
  organization you want to collect from.
* Select **Create Service Account**, name it `ccm-readonly`, and finish
  creation without granting project-level roles yet.

## Grant the read-only role at the organization level

* Navigate to the organization's **IAM & Admin** > **IAM** page (not the
  project's) — Security Command Center findings/assets are
  organization-scoped, so the role must be granted at the organization,
  not the project.
* Select **Grant Access**, add the service account, and assign the
  **Security Center Assets Viewer** (`roles/securitycenter.assetsViewer`)
  and **Security Center Findings Viewer**
  (`roles/securitycenter.findingsViewer`) roles — both read-only.

## Create and download a key

* Back on the service account's page, navigate to the **Keys** tab.
* Select **Add Key** > **Create new key** > **JSON**.
* Download the resulting JSON file and store it securely — this is a
  long-lived credential; treat it like a password.

## Record the credentials

| Value | Config key | Environment variable |
| --- | --- | --- |
| Path to the downloaded service account JSON file | `service_account_json_path` | `GCP_SCC_SERVICE_ACCOUNT_JSON_PATH` |
| Organization ID (numeric, from **IAM & Admin** > **Settings** at the org level) | `organization_id` | `GCP_SCC_ORGANIZATION_ID` |
