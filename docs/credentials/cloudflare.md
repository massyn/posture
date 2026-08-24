# Cloudflare — credential setup

[← back to collector docs](../collectors/cloudflare.md)

These steps create a scoped, read-only API token for the CCM integration.
Cloudflare's custom-token flow lets you grant exactly the permission groups
needed, with no separate service-account step.

## Create the API token

* Log in to the Cloudflare dashboard.
* Select your user icon (top right) > **My Profile** > **API Tokens**.
* Select **Create Token**, then select **Create Custom Token**.
* Set the **Token name** to `CCM - Read Only`.
* Under **Permissions**, add:
    * **Zone** — **Zone** — **Read**
    * **Zone** — **DNS** — **Read**
* Under **Zone Resources**, choose **Include** > **All zones** (or select
  specific zones if the token should only cover a subset).
* Select **Continue to summary**, review, then select **Create Token**.
* Copy the token value immediately — it is only shown once.

## Record the credentials

Store the following value securely — it maps directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| API Token | `api_token` | `CLOUDFLARE_API_TOKEN` |

There is no separate account/zone identifier to record — the token itself
determines which zones are visible, and the collector's base URL
(`https://api.cloudflare.com/client/v4`) is fixed.
