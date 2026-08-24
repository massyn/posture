# ServiceNow — credential setup

[← back to collector docs](../collectors/servicenow.md)

These steps create a dedicated service account with read-only access for the
CCM integration, using ServiceNow basic auth. The collector also supports an
OAuth2 resource-owner password grant (`auth_type=oauth2`, the default) if
your instance requires it instead — talk to your ServiceNow admin about
which mode your instance expects; the role assignment below applies either
way.

## Create the service account

* Log in to your ServiceNow instance as an administrator.
* Navigate to **User Administration** > **Users**.
* Select **New**.
* Fill in the following fields:
    * **User ID**: `ccm_readonly`
    * **First name**: `CCM`
    * **Last name**: `Read Only`
    * **Email**: enter an appropriate service account email address
    * **Password**: generate a strong password and store it securely
* Tick **Web service access only** to prevent interactive logins.
* Select **Submit**.

## Assign roles

* Open the user record you just created.
* Scroll to the **Roles** related list at the bottom of the form.
* Select **Edit**.
* Search for and add the following roles:
    * `DATA_READER`
    * `sn_vul.vulnerability_read`
* Select **Save**.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Instance name (e.g. `yourinstance` for `https://yourinstance.service-now.com`) | `instance` | `SERVICENOW_INSTANCE` |
| User ID | `username` | `SERVICENOW_USERNAME` |
| Password | `password` | `SERVICENOW_PASSWORD` |

If your instance requires the OAuth2 flow instead of basic auth, set
`auth_type=oauth2` and provide `client_id`/`client_secret` in addition to
`username`/`password` (`SERVICENOW_AUTH_TYPE`, `SERVICENOW_CLIENT_ID`,
`SERVICENOW_CLIENT_SECRET`) — your ServiceNow admin provisions the OAuth
application registration separately from the service account above.
