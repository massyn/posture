# Qualys — credential setup

[← back to collector docs](../collectors/qualys.md)

These steps create a dedicated user account with read-only access for the
CCM integration.

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
* Select **Save**.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Platform URL (e.g. `https://qualysapi.qualys.com`) | `base_url` | `QUALYS_BASE_URL` |
| Username | `username` | `QUALYS_USERNAME` |
| Password | `password` | `QUALYS_PASSWORD` |
