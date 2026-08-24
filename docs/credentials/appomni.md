# AppOmni — credential setup

[← back to collector docs](../collectors/appomni.md)

These steps create a dedicated OAuth application and long-lived access
token for the CCM integration. AppOmni's token manager doesn't offer a
role-based read-only flag on the token itself — access is governed by the
role assigned to whichever user account is used to manage the token — so
provision a dedicated user with the minimum admin capability needed (User
Manager, so it can hold the OAuth Token Manager permission below) rather
than reusing a personal admin account.

## Create the OAuth application and token

* Log in to your AppOmni console as an administrator.
* Navigate to **Settings** > **API Settings**.
* Select **+ Add Application**, then select **Create new OAuth application**.
* In the application's **Actions** column, select the three-dot menu and
  choose **Manage Tokens**.
* Select **+ OAuth Token** in the upper-right corner.
* Set an appropriate **Expiry date** (e.g. a year out — there is no
  indefinite option), add a short description (`CCM - Read Only`), and
  select **Save**.
* Copy the **Access Token** and **Refresh Token** immediately and store
  them securely.

## Assign token-management access

* In **User Management**, ensure the account that owns this application has
  the **OAuth Token Manager** permission (an admin can grant this without
  making the account a full admin).

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Access Token | `access_token` | `APPOMNI_ACCESS_TOKEN` |
| Instance (the `<instance>` in `https://<instance>.appomni.com`) | `instance` | `APPOMNI_INSTANCE` |

**Caveat:** AppOmni's own docs describe the OAuth token's *access* as tied
to the granting user's role/permissions rather than a token-level
read/write toggle — there is no documented way to mint a token that is
read-only at the API level. Scope the granting account's role as narrowly
as your AppOmni tenant's role model allows (least-privilege, not a
guaranteed read-only enforcement) and treat the token as sensitive
accordingly.
