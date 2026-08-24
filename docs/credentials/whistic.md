# Whistic — credential setup

[← back to collector docs](../collectors/whistic.md)

These steps create a Whistic Public API key for the CCM integration. API
key generation requires Whistic Admin privileges; Whistic does not document
a lower-privilege or read-only role for API key issuance, so this must be
done by (or delegated to) an existing Whistic Admin — see the caveat below.

## Generate the API key

* Log in to Whistic as an Admin.
* Select **Settings** in the top navigation, then select **Integrations**.
* Find the **Whistic Public API** tile and select **Configure**.
* Select **Generate New Key**.
* Enter a label of `CCM - Read Only`.
* Whistic generates and displays the key — copy it immediately and store it
  securely (Whistic keys do not expire, so treat this as a long-lived
  secret).

## Record the credentials

Store the following value securely — it maps directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| API Key | `token` | `WHISTIC_TOKEN` |

`endpoint` (`WHISTIC_ENDPOINT`) is optional — it defaults to Whistic's
public API host (`https://public.whistic.com/api`).

**Caveat:** Whistic's own documentation does not describe a read-only key
type or scoped permission model for Public API keys — a generated key
carries whatever access the Whistic Public API exposes to Admins as a
whole, not a narrower read-only grant. This collector (`vendors`,
`vendor_details`) only performs `GET` requests, but the key itself is not
restricted from Whistic's write endpoints at the platform level.
