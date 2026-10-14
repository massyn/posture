# Qualys TotalAppSec — credential setup

[← back to collector docs](../collectors/qualys_tas.md)

These steps create a dedicated user account with read-only access to
TotalAppSec (Web Application Scanning) for the CCM integration. If you have
already created the `ccm_readonly` user for the [Qualys VMDR
collector](qualys.md), you can reuse it: give it the TotalAppSec module and
web application scope below, and set the same values under the `QUALYS_TAS_*`
environment variables.

**Unverified:** these steps follow Qualys's public documentation and have
not been checked against a live subscription. Menu labels vary between
Qualys releases — verify each step on your own subscription.

## Create the user account

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

## Grant TotalAppSec access

* Open the **Administration** (or **Users**) module and edit the
  `ccm_readonly` user's roles and scope.
* Give the user access to the **TotalAppSec / Web Application Scanning**
  module.
* Set the user's web application scope to every web application the
  collection should cover — typically all of them. A user scoped to a subset
  produces a snapshot of that subset only, with no error to say so.

Subscription-level OAuth clients cannot be used: Qualys does not accept them
on any Web Application Scanning endpoint.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| API server URL (e.g. `https://qualysapi.qualys.com`) | `base_url` | `QUALYS_TAS_BASE_URL` |
| Username | `username` | `QUALYS_TAS_USERNAME` |
| Password | `password` | `QUALYS_TAS_PASSWORD` |
