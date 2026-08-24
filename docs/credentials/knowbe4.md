# KnowBe4 — credential setup

[← back to collector docs](../collectors/knowbe4.md)

These steps generate a Reporting API token in the KnowBe4 console. The
Reporting API is inherently read-only (it has no write endpoints), so there
is no separate role/scope to restrict beyond enabling the API itself.

## Enable and generate the token

* Log in to your KnowBe4 console (KSAT) as an administrator.
* Select your email address in the top-right corner and select
  **Account Settings**.
* Navigate to **Account Integrations** > **API**.
* Under **Reporting API**, toggle **Enable Report API Access** on.
* Select **Reporting API** to open the Reporting API subtab.
* In the top-right corner, select **+ Create New API Token**.
* Enter a descriptive name, e.g. `CCM - Read Only`, and ensure **Status** is
  enabled.
* Select **Create Token**.
* Copy the token value immediately from the confirmation pop-up — it is not
  shown again after the window closes.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Reporting API token | `token` | `KNOWBE4_TOKEN` |

### Optional

| Value | Config key | Environment variable |
| --- | --- | --- |
| Region (`us` or `eu`; defaults to `us`) — must match the region your KnowBe4 console is hosted in | `region` | `KNOWBE4_REGION` |
