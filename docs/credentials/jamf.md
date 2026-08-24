# Jamf — credential setup

[← back to collector docs](../collectors/jamf.md)

These steps create a dedicated API client with read-only access for the CCM
integration, using Jamf Pro's API Roles and Clients feature (Jamf Pro 10.35+).
This uses OAuth2 client credentials (client ID and secret), not a username
and password.

## Create the API role

* Log in to your Jamf Pro instance as an administrator.
* Navigate to **Settings** > **System** > **API Roles and Clients**.
* Select the **API Roles** tab and select **New**.
* Set the **Display Name** to `CCM - Read Only`.
* Under **Privileges**, enable the following **Read** permissions:
    * Computers
    * Computer Management
    * Computer Inventory Collection
    * Mobile Devices
    * Mobile Device Management
    * Policies
    * Configuration Profiles
    * macOS Configuration Profiles
    * Users
    * Buildings
    * Departments
    * Categories
* Select **Save**.

## Create the API client

* Select the **API Clients** tab and select **New**.
* Fill in the following fields:
    * **Display Name**: `CCM - Read Only`
    * **Enabled**: tick to enable
    * **Access Token Lifetime**: set to an appropriate value (e.g. 30 minutes)
* Under **API Roles**, add the `CCM - Read Only` role created above.
* Select **Save**.
* On the saved record, select **Generate Client Secret**.
* Copy the **Client ID** and **Client Secret** immediately — the secret is
  only shown once.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Jamf Pro URL (e.g. `https://yourinstance.jamfcloud.com`) | `url` | `JAMF_URL` |
| Client ID | `client_id` | `JAMF_CLIENT_ID` |
| Client secret | `client_secret` | `JAMF_CLIENT_SECRET` |
