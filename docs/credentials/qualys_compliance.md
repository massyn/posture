# Qualys Policy Compliance — credential setup

[← back to collector docs](../collectors/qualys_compliance.md)

This collector uses the same Qualys API credentials and `QUALYS_*`
environment variables as the [Qualys VMDR collector](qualys.md). If you have
already created the `ccm_readonly` user there, you only need to make sure it
can see Policy Compliance data (below) — no new credentials.

**Unverified:** these steps follow Qualys's public documentation and have
not been checked against a live subscription. Menu labels vary between
Qualys releases — verify each step on your own subscription.

## Create the user account

If the `ccm_readonly` user doesn't exist yet:

* Log in to your Qualys subscription as an administrator.
* Navigate to **Users** > **Users** and select **New** > **User**.
* Fill in the following fields:
    * **First name**: `CCM`
    * **Last name**: `Read Only`
    * **Email**: enter an appropriate service account email address
    * **Username**: `ccm_readonly`
    * **Password**: generate a strong password and store it securely
* Under **User Role**, select **Reader**.
* Make sure **API** access is allowed for the user.
* Select **Save**.

## Grant Policy Compliance access

* Edit the `ccm_readonly` user and give it access to the **Policy
  Compliance** module.
* Give the user's asset scope (asset groups or tags) every host the
  collection should cover. Posture data is only returned for hosts the user
  can see; a user scoped to a subset produces a snapshot of that subset only,
  with no error to say so.
* Every compliance policy is listed regardless of scope, but posture rows
  only appear for in-scope hosts.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Platform URL (e.g. `https://qualysapi.qualys.com`) | `base_url` | `QUALYS_BASE_URL` |
| Username | `username` | `QUALYS_USERNAME` |
| Password | `password` | `QUALYS_PASSWORD` |
