# Google Workspace — credential setup

[← back to collector docs](../collectors/google_workspace.md)

These steps create a service account with **domain-wide delegation**,
authorized for exactly the read-only Admin SDK scopes this collector needs,
impersonating a real super admin (required — the Directory API only works
via impersonation, never as the service account itself). Auth is a
JWT-bearer exchange (`posture.collectors._google_oauth`), not a plain
API key.

## Create the service account

* In [Google Cloud Console](https://console.cloud.google.com), select (or
  create) the project that will own this integration.
* Navigate to **IAM & Admin** > **Service Accounts** > **Create Service
  Account**.
* Name it `ccm-readonly`, and skip granting it any project-level IAM roles
  — this service account never calls Google Cloud APIs directly, only the
  Admin SDK via domain-wide delegation, which is authorized separately in
  the Workspace Admin console (next section), not through IAM.
* Open the new service account, navigate to **Keys** > **Add Key** >
  **Create new key**, choose **JSON**, and download it. This file is the
  `service_account_json_path` credential — store it securely; it is only
  downloadable once.
* Note the service account's **Client ID** (a numeric value, on the
  service account's **Details** tab) — you'll need it for the next step.

## Authorize domain-wide delegation

* Sign in to the [Google Workspace Admin console](https://admin.google.com)
  as a Super Administrator.
* Navigate to **Security** > **Access and data control** > **API controls**
  > **Domain-wide delegation** > **Add new**.
* **Client ID**: the numeric Client ID noted above.
* **OAuth scopes**: add every scope below in one entry (comma-separated) —
  this collector requests the full set in a single token, so a domain
  missing even one causes every resource to fail, not just the one needing
  it (see the collector's own docstring for why):

    ```
    https://www.googleapis.com/auth/admin.directory.user.readonly,
    https://www.googleapis.com/auth/admin.directory.group.readonly,
    https://www.googleapis.com/auth/admin.directory.group.member.readonly,
    https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly,
    https://www.googleapis.com/auth/admin.directory.orgunit.readonly
    ```

* Select **Authorize**.

## Choose the impersonated admin

The collector's `admin_email` config is a real user in your domain — the
Directory API only accepts requests made *as* an existing admin (domain-wide
delegation impersonates them), never as the service account's own identity.
Use a dedicated automation admin account if your org has one; otherwise a
Super Administrator's address works, since the actual permission boundary
is the OAuth scopes authorized above, not this account's own role — the
service account can't do anything beyond those scopes no matter who it
impersonates.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Path to the downloaded service account JSON key file | `service_account_json_path` | `GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON_PATH` |
| Impersonated admin's email address | `admin_email` | `GOOGLE_WORKSPACE_ADMIN_EMAIL` |

### Optional

| Value | Config key | Environment variable |
| --- | --- | --- |
| Customer ID (defaults to `my_customer`, Google's alias for "your own domain") — only set this for a reseller/multi-customer setup | `customer_id` | `GOOGLE_WORKSPACE_CUSTOMER_ID` |
