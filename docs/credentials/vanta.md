# Vanta — credential setup

[← back to collector docs](../collectors/vanta.md)

These steps create a dedicated "Manage Vanta" OAuth application scoped to
read-only access for the CCM integration, using Vanta's API OAuth2
client-credentials flow.

## Create the application

* Log in to your Vanta account as an Administrator.
* Navigate to the **Developer Console** (Settings > API, or
  `https://app.vanta.com/settings/api` depending on your Vanta plan).
* Select **Create new application** (or **Manage applications** > **New**).
* Fill in the following field:
    * **Name**: `CCM - Read Only`
* Choose **Manage Vanta** as the application type (this is the type that
  exposes the resource-scoped API used by this collector).
* Under **Scopes**, grant read access to the resources this collector
  needs. Prefer the narrowest resource-scoped read permissions Vanta's
  console offers (e.g. `vanta-api.controls:read`,
  `vanta-api.documents:read`, `vanta-api.frameworks:read`,
  `vanta-api.groups:read`, `vanta-api.integrations:read`,
  `vanta-api.monitored-computers:read`, `vanta-api.people:read`,
  `vanta-api.tests:read`, `vanta-api.vulnerabilities:read`) over the broad
  `vanta-api.all:read` scope, if your Vanta plan's console lists them
  individually — fall back to `vanta-api.all:read` if it doesn't.
* Select **Create** (or **Save**).
* Copy the generated **Client ID** and **Client Secret** immediately —
  the secret is only shown once.

**Caveat:** exact console labels above (menu names, whether resource-scoped
read permissions are exposed individually vs. only as `vanta-api.all:read`)
were not confirmed against a live Vanta tenant — Vanta's UI varies somewhat
by plan/tier. Confirm the exact navigation and available scopes against
your own tenant before relying on this doc.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Client ID | `client_id` | `VANTA_CLIENT_ID` |
| Client Secret | `client_secret` | `VANTA_CLIENT_SECRET` |
