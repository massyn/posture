# runZero — credential setup

[← back to collector docs](../collectors/runzero.md)

These steps create a dedicated, read-only export API key for the CCM
integration. runZero's Export API keys are export-only by design — they
carry no write capability regardless of the console user they're generated
under, but a dedicated key still keeps the credential's provenance clear for
audit.

## Create the export API key

* Log in to the runZero console.
* Select your organization (or the specific org this key should be scoped
  to — a token is scoped to one org's asset inventory).
* Go to **Organization Settings** > **API** (or **Account** > **API Keys**,
  depending on console version).
* Under **Export API Keys**, select **Create Export API Key**.
* Name it `CCM - Read Only`.
* Copy the key value immediately — it is only shown once.

If the runZero console is self-hosted (on-prem/private cloud) rather than
the SaaS console, note the console's own base URL — it's needed for the
`endpoint` config below.

## Record the credentials

Store the following values securely — they map directly to the collector's
config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Export API Key | `token` | `RUNZERO_TOKEN` |
| Console base URL (optional; only if self-hosted) | `endpoint` | `RUNZERO_ENDPOINT` |

`endpoint` defaults to `https://console.runzero.com/api/v1.0` (the SaaS
console) when unset.
