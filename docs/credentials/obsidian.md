# Obsidian Security — credential setup

[← back to collector docs](../collectors/obsidian.md)

These steps create a dedicated, read-only API token for the CCM integration.

## Create the API token

* Log in to the Obsidian Security console as an admin.
* Go to **Settings** > **API Tokens** (or **Integrations** > **API Access**,
  depending on console version).
* If Obsidian's role model supports a dedicated read-only/viewer role,
  provision a separate user in that role first and generate the token under
  that user rather than an admin account — Obsidian's API tokens otherwise
  inherit the generating user's own permissions.
* Select **Generate Token**, name it `CCM - Read Only`.
* Copy the token value immediately — it is only shown once.

## Record the credentials

Store the following value securely — it maps directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| API Token | `token` | `OBSIDIAN_TOKEN` |
| Endpoint (optional; only if not on the default host) | `endpoint` | `OBSIDIAN_ENDPOINT` |

`endpoint` defaults to `https://api.obsec.io/v1/gql` when unset.
