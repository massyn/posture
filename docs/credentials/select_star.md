# Select Star — credential setup

[← back to collector docs](../collectors/select_star.md)

These steps create a dedicated, read-only API token for the CCM
integration.

## Create the API token

* Log in to Select Star as a workspace admin.
* Go to **Settings** > **API** (or **Integrations** > **API Access**,
  depending on workspace plan).
* If Select Star's role model supports a dedicated read-only/viewer role,
  provision a separate user in that role first and generate the token under
  that user rather than an admin account — Select Star's API tokens
  otherwise inherit the generating user's own permissions.
* Select **Generate Token** (or **Create API Key**), name it
  `CCM - Read Only`.
* Copy the token value immediately.

## Record the credentials

Store the following value securely — it maps directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| API Token | `token` | `SELECTSTAR_TOKEN` |
| Endpoint (optional; only if not on the default SaaS host) | `endpoint` | `SELECTSTAR_ENDPOINT` |

`endpoint` defaults to `https://api.production.selectstar.com` when unset.
