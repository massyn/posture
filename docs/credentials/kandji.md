# Kandji — credential setup

[← back to collector docs](../collectors/kandji.md)

Kandji has rebranded to "Iru", but existing tenants still authenticate the
same way and resolve at the same `https://<subdomain>.api.kandji.io` (or
`.api.eu.kandji.io` for EU tenants) host. Kandji API tokens are tied to
whichever user creates them — Kandji's own guidance is to create a
dedicated service user first, rather than generating a token under a
personal admin account, so a departing admin's account being disabled
doesn't silently break the integration.

## Create a dedicated service user (recommended)

* Log in to the Kandji console as an administrator.
* Navigate to **Settings** > **Access** > **Users**, and create a new user
  for the integration (e.g. `ccm-readonly@yourdomain.com`) with the
  narrowest admin role Kandji's console offers that still permits reading
  device/blueprint/vulnerability data.

## Generate the API token

* Sign in as that service user (or, if your Kandji instance ties tokens to
  the creating session either way, ensure you're acting as the intended
  owner).
* Navigate to **Settings** > **Access**.
* Scroll to **API Token** and select **Add API Token**.
* Enter a **Name** (`CCM - Read Only`) and a short **Description**, then
  select **Create**.
* Copy the generated token immediately — Kandji does not show it again —
  then select **Next**.
* On the permissions screen, select **Configure** and grant read access
  only to Devices, Blueprints, and Vulnerability Management (skip write/
  action scopes such as device commands, lock/wipe, or app deployment).

## Find your API URL

* Still under **Settings** > **Access**, note the tenant's API URL —
  `https://<subdomain>.api.kandji.io` (US) or
  `https://<subdomain>.api.eu.kandji.io` (EU).

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| API URL | `api_url` | `KANDJI_API_URL` |
| API Token | `api_token` | `KANDJI_API_TOKEN` |

**Caveat:** whether Kandji's per-token permission screen actually lets you
restrict a token to read-only per resource (vs. an all-or-nothing token
scoped only by the creating user's own role) was not independently
confirmed against a live tenant — verify the options your console actually
presents and scope as narrowly as they allow.
