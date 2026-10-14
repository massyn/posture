# CyberArk Privileged Access Manager — credential setup

[← back to collector docs](../collectors/cyberark.md)

These steps create a dedicated, read-only service identity for the CCM
integration. The collector reads account metadata, safes and safe membership
only — it never retrieves a password, so the identity must **not** be given
**Retrieve accounts** or **Use accounts** on any safe.

The collector only sees safes the identity is a member of. A safe it isn't a
member of is silently missing from the snapshot, so add it to every safe the
collection should cover.

**Unverified:** these steps follow CyberArk's public documentation and
third-party integration guides, and have not been checked against a live
tenant. Menu labels vary between versions — verify each step on your own
deployment.

Follow **one** of the two sections below, depending on your deployment.

## Privilege Cloud (Shared Services)

### Create the service user

* Log in to **Identity Administration** as an administrator.
* Go to **Core Services** > **Users** and select **Add User**.
* Set the login name to e.g. `ccm-readonly@<your-suffix>` and generate a
  strong password.
* Under **Status**, tick **Is service user** and **Is OAuth confidential
  client**, then select **Create User**.
* Go to **Roles** and add the user to a **Privilege Cloud Users** role (not
  an administrators role).

### Grant safe access

* In Privilege Cloud, open each safe to cover (**Policies** > **Access
  Control (Safes)**) and add the service user as a member.
* Grant only **List accounts** and **View Safe members**. Leave every other
  permission, including **Use accounts** and **Retrieve accounts**, unticked.

### Find the URLs

* **Privilege Cloud URL** — the portal host, e.g.
  `https://<subdomain>.privilegecloud.cyberark.cloud`.
* **Identity URL** — the Identity tenant host, e.g.
  `https://<tenant-id>.id.cyberark.cloud`. The tenant id is often *not* the
  Privilege Cloud subdomain; take it from the Identity Administration URL.

## Self-hosted PAM (PVWA) or Privilege Cloud Standard

### Create the user

* In the PVWA, go to **Administration** > **Users and Groups** (or the
  PrivateArk Client on older versions) and create a vault user, e.g.
  `CCM_ReadOnly`, with a strong password. An LDAP user also works — set
  `logon_type` to `LDAP` below.
* Give it no vault authorisations (it needs no administrative rights).

### Grant safe access

* Add the user as a member of each safe to cover, granting only **List
  accounts** and **View Safe members**. Leave **Use accounts**, **Retrieve
  accounts** and every management permission unticked.

### Certificates

* If the PVWA presents a certificate signed by an internal CA, export that CA
  (and any intermediates) as a PEM bundle for `ca_bundle` below.
* `insecure` disables certificate verification altogether. It exposes the
  user's password to anyone able to intercept the connection, so prefer
  `ca_bundle` wherever possible.

## Record the credentials

| Value | Config key | Environment variable |
| --- | --- | --- |
| PVWA / Privilege Cloud URL | `base_url` | `CYBERARK_BASE_URL` |
| Username (service user / vault user) | `username` | `CYBERARK_USERNAME` |
| Password | `password` | `CYBERARK_PASSWORD` |
| Identity URL (Privilege Cloud Shared Services only) | `identity_url` | `CYBERARK_IDENTITY_URL` |
| Logon type, self-hosted only (`CyberArk` default, `LDAP`, `RADIUS`, `Windows`) | `logon_type` | `CYBERARK_LOGON_TYPE` |
| Path to a PEM CA bundle (optional) | `ca_bundle` | `CYBERARK_CA_BUNDLE` |
| Disable certificate verification (optional, `true`/`false`) | `insecure` | `CYBERARK_INSECURE` |

Setting `identity_url` selects Privilege Cloud OAuth authentication; leaving
it unset selects the PVWA Logon API. `ca_bundle` and `insecure` are mutually
exclusive.
