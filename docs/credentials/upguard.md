# UpGuard — credential setup

[← back to collector docs](../collectors/upguard.md)

UpGuard issues exactly one API key/secret pair per account, tied to
whichever account enables API access — there is no separate scoped
service-account or read-only role for API keys. Provision this under a
dedicated account with the narrowest UpGuard user role your plan supports
(rather than a personal admin login) if your organization has multiple
UpGuard seats; on single-seat accounts, the account owner's own key is the
only option.

## Enable API access and generate the key

* Log in to UpGuard.
* Select your account name (top right), then select **Manage…**.
* Enable **API Access** — this generates a **Service API Key** and
  **Secret Key** the first time it's turned on. Only one secret key exists
  per account; re-enabling does not rotate it.
* Copy both values and store them securely.

## Record the credentials

UpGuard's own API expects the Authorization header formed as
`Token token="<Service API Key><Secret Key>"` (the two values concatenated,
no separator) — this collector's `api_key` config holds that complete
header value, not just the bare key.

| Value | Config key | Environment variable |
| --- | --- | --- |
| `Token token="<Service API Key><Secret Key>"` (concatenated) | `api_key` | `UPGUARD_API_KEY` |

`base_url` (`UPGUARD_BASE_URL`) is optional — only set it if your account
is provisioned on a non-default UpGuard API host.

**Caveat:** UpGuard's API key is account-wide — there is no documented
mechanism to scope it to read-only access. Treat it as full-access and
restrict which account it's generated under accordingly.
