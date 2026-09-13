# Cisco Duo — credential setup

[← back to collector docs](../collectors/duo.md)

These steps create a dedicated Duo Admin API application scoped to
read-only access, rather than reusing an existing integration's keys.

## Create the Admin API application

* Sign in to the [Duo Admin Panel](https://admin.duosecurity.com) as an
  administrator with the **Grant applications** permission.
* Navigate to **Applications** > **Protect an Application**.
* Search for **Admin API** and select **Protect**.
* Name it `CCM - Read Only`.

## Grant read-only permissions

* On the application's settings page, under **Permissions**, select only
  **Grant read resource** — this is the minimum needed for the collector's
  `users`/`groups`/`endpoints`/`phones`/`tokens` resources. Do not grant
  **Grant write resource** or **Grant admin**.
* Save the application.

## Record the credentials

Copy the following values from the application's settings page — these map
directly to the collector's required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| API hostname (e.g. `api-xxxxxxxx.duosecurity.com`) | `api_hostname` | `DUO_API_HOSTNAME` |
| Integration key | `integration_key` | `DUO_INTEGRATION_KEY` |
| Secret key | `secret_key` | `DUO_SECRET_KEY` |

Store the secret key securely — Duo shows it only once, at creation time.
