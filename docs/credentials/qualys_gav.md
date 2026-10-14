# Qualys Global AssetView — credential setup

[← back to collector docs](../collectors/qualys_gav.md)

These steps create a dedicated user account with read-only access to Global
AssetView / CyberSecurity Asset Management (CSAM) for the CCM integration.
If you have already created the `ccm_readonly` user for the [Qualys VMDR
collector](qualys.md), you can reuse it: give it the access below and set the
same username and password under the `QUALYS_GAV_*` environment variables.

**Unverified:** these steps follow Qualys's public documentation and have
not been checked against a live subscription. Menu labels vary between
Qualys releases — verify each step on your own subscription.

## Create the user account

If the `ccm_readonly` user doesn't exist yet:

* Log in to your Qualys subscription as an administrator.
* Navigate to **Users** > **Users** and select **New** > **User**.
* Fill in the following fields:
    * **First name**: `CCM`
    * **Last name**: `Read Only`
    * **Email**: enter an appropriate service account email address
    * **Username**: `ccm_readonly`
    * **Password**: generate a strong password and store it securely
* Under **User Role**, select **Reader**.
* Make sure **API** access is allowed for the user.
* Select **Save**.

## Grant Global AssetView access

* Edit the `ccm_readonly` user's roles and permissions and give it access to
  the **Global AssetView** (or **CyberSecurity Asset Management**) module,
  including its API permission.
* Give the user's asset scope every asset the collection should cover —
  typically all assets. A user scoped to a subset produces a snapshot of that
  subset only, with no error to say so.

Qualys doesn't state whether the free Global AssetView tier includes this
API or only paid CSAM; if authentication succeeds but the asset search is
refused, check the subscription's entitlement.

## Find the gateway URL

This collector talks to the subscription's **gateway** host, not the
`qualysapi` host the other Qualys collectors use. It is listed under **Help**
> **About** in the Qualys portal, and follows the platform's pattern, e.g.
`https://gateway.qg1.apps.qualys.com` for US Platform 1.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Gateway URL (e.g. `https://gateway.qg1.apps.qualys.com`) | `gateway_url` | `QUALYS_GAV_GATEWAY_URL` |
| Username | `username` | `QUALYS_GAV_USERNAME` |
| Password | `password` | `QUALYS_GAV_PASSWORD` |
