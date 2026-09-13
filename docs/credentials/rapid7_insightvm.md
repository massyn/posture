# Rapid7 InsightVM — credential setup

[← back to collector docs](../collectors/rapid7_insightvm.md)

This collector uses the Insight platform API key (not the on-premise
InsightVM console's Security Console API) — a static key with no
independent read-only scope, so generate it from a dedicated Insight
platform user rather than a personal admin's.

## Generate the API key

* Sign in to the [Insight platform](https://insight.rapid7.com) as the
  user the integration should run as.
* Navigate to the user's account settings (avatar menu) > **API Keys**.
* Select **New API Key**, name it `CCM - Read Only`, and copy the value
  immediately — it is only shown once.

## Identify your region

Your Insight platform region determines the API host. It's visible in the
URL when you're signed in (e.g. `https://us.api.insight.rapid7.com` → `us`).
Valid values: `us`, `us2`, `us3`, `eu`, `ca`, `au`, `ap`.

## Record the credentials

| Value | Config key | Environment variable |
| --- | --- | --- |
| API Key | `api_key` | `RAPID7_INSIGHTVM_API_KEY` |
| Region | `region` | `RAPID7_INSIGHTVM_REGION` |

`region` is optional (defaults to `us`); `endpoint`
(`RAPID7_INSIGHTVM_ENDPOINT`) is an optional override if you need to point
at a host other than the standard `https://<region>.api.insight.rapid7.com`.

**Caveat:** the Insight platform API key has no read-only flag — it is
full-access to whatever the generating user can reach, so least privilege
here means provisioning a dedicated user with only vulnerability-management
read access, not a key permission configured at generation time.
