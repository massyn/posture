# Tenable.io — credential setup

[← back to collector docs](../collectors/tenableio.md)

Tenable.io API keys are generated per-user and inherit that user's own
role — there is no separate scoped-token concept. These steps create a
dedicated user with Tenable.io's **Basic** role (read-only) so the
resulting keys carry the minimum access available, rather than reusing a
personal admin account.

## Create the user account

* Log in to Tenable.io (`cloud.tenable.com`) as an administrator.
* Navigate to **Settings** > **Access Control** > **Users**, and create a
  new user (e.g. `ccm-readonly@yourdomain.com`).
* Assign the **Basic** role — Tenable.io's lowest-privilege role, read-only
  across scans/assets/vulnerabilities.

## Generate the API keys

* Sign in to Tenable.io **as that user** (API keys are generated per-account
  from **My Account**, not centrally by an admin on the user's behalf).
* Select the user profile icon (top right) to open **My Account**.
* In the left navigation, select **API Keys**.
* Select **Generate** in the bottom-left corner, and confirm — this
  invalidates any existing keys for the account (only one active key pair
  per user at a time).
* Copy the **Access Key** and **Secret Key** immediately — Tenable.io only
  displays them once; they cannot be retrieved again after leaving the
  page.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Access Key | `access_key` | `TENABLEIO_ACCESS_KEY` |
| Secret Key | `secret_key` | `TENABLEIO_SECRET_KEY` |
