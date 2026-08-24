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
    * **Zone** — **Workers Routes** — **Read** (for `workers_routes`)
    * **Account** — **Cloudflare Pages** — **Read** (for `pages_projects`)
    * **Account** — **Workers Scripts** — **Read** (for `workers_scripts`)
* Under **Zone Resources**, choose **Include** > **All zones** (or select
  specific zones if the token should only cover a subset).
* Under **Account Resources** (shown once an **Account**-level permission is
  added), choose **Include** > **All accounts** (or a specific account) —
  needed because `pages_projects`/`workers_scripts` are account-scoped, not
  zone-scoped; the collector derives the account id list from the zones the
  token can already see, so it must also have read access at the account
  level for those same accounts.
* Select **Continue to summary**, review, then select **Create Token**.
* Copy the token value immediately — it is only shown once.

A token missing the Account-level permissions still works for the
zone-scoped resources (`zones`, `dns_records`, `cdn_protected_domains`,
`workers_routes`) — `pages_projects`/`workers_scripts` just fail for that
token with an `IncompleteCollection`, same as any other resource whose
required permission is missing.

## Record the credentials

Store the following value securely — it maps directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| API Token | `api_token` | `CLOUDFLARE_API_TOKEN` |

There is no separate account/zone identifier to record — the token itself
determines which zones are visible, and the collector's base URL
(`https://api.cloudflare.com/client/v4`) is fixed.
