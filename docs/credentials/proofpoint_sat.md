# Proofpoint Security Awareness Training — credential setup

[← back to collector docs](../collectors/proofpoint_sat.md)

These steps generate a Results (reporting) API token in the Proofpoint
Security Awareness Training (PSAT, now branded ZenGuide) platform. The
Results API is read-only: it has no write endpoints.

> **Unverified:** the menu path below comes from third-party integration
> guides (Living Security, Anzenna), not Proofpoint's own documentation, and
> differs between portal versions. Confirm it against your own console.

## Generate the token

* Sign in to the PSAT platform as a **Super Admin** (or an admin holding the
  Reporting Admin role); only administrators can create API tokens.
* Open the admin menu and go to **Settings** (shown as a gear icon,
  **Company Settings**, on some portal versions).
* Under **Integrations** / **API**, open **Results API** (labelled
  **Token Mart** or **API Tokens** on some portal versions). If neither
  appears, the feature needs enabling for your tenant; ask your Proofpoint
  account team.
* Create a new token named `CCM - Read Only`. Where the console offers a
  role or permission choice, pick the **Reporting** / Reporting API option
  so the token can only read reports.
* Copy the token value immediately. It is shown only once; if you lose it,
  revoke it and generate a new one.

## Choose the region

The API host depends on where your tenant is hosted. Match it to the host
your PSAT console's results/reporting pages use:

| Region value | API host |
| --- | --- |
| `us` (default) | `results.us.securityeducation.com` |
| `eu` | `results.eu.securityeducation.com` |
| `ap` | `results.ap.securityeducation.com` |
| `ca` | `results.zenguide.ca` |
| `in` | `results.securityeducation.in` |

## Record the credentials

Store the following values securely. They map directly to the collector's
config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Results API token | `token` | `PROOFPOINT_SAT_TOKEN` |

### Optional

| Value | Config key | Environment variable |
| --- | --- | --- |
| Region (`us`, `eu`, `ap`, `ca` or `in`; defaults to `us`) | `region` | `PROOFPOINT_SAT_REGION` |

## Note on `phishing_extended`

PSAT also has a `phishing_extended` report (per-click event detail). It is
disabled by default in every tenant and this collector does not read it.
