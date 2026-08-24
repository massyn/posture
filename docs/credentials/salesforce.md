# Salesforce — credential setup

[← back to collector docs](../collectors/salesforce.md)

Auth here is username + password + security token — the credentials a
Salesforce admin issues directly to a user, not a connected app (no
consumer key/secret needed). These steps create a dedicated integration
user on a minimal, read-only profile rather than reusing a personal login.

This org's collector reads five custom objects (see
`src/posture/collectors/salesforce.json`): `fixed_asset__c`,
`krow__location__c`, `krow__project_resources__c`, `domain__c`, and
`krow__team__c`. The profile/permission set below must grant **Read**
object- and field-level access to those objects specifically — Salesforce
security review each time a new object is added to that file.

## Create the integration user

* Log in to Salesforce as an administrator.
* Navigate to **Setup** > **Users** > **Users**, and select **New User**.
* Fill in the standard fields (name, username, email) for a dedicated
  service account (e.g. `ccm-readonly@yourorg.com`).
* Assign a minimal profile: start from **Minimum Access - Salesforce** (or
  **Minimum Access - API Only Integrations**, Salesforce's newer
  least-privilege profile built for API-only integration users) rather
  than a standard user profile.
* Ensure **API Enabled** is granted (required on the profile/permission set
  for any API access at all).

## Grant read access to the required objects

* Via a **Permission Set** (preferred over editing the base profile
  directly): create one named `CCM - Read Only`, grant **Read** object- and
  field-level access to `Fixed_Asset__c`, `krow__Location__c`,
  `krow__Project_Resources__c`, `Domain__c`, and `krow__Team__c`, and
  assign it to the integration user.
* Do not grant Create/Edit/Delete on any object — this integration is
  read-only.

## Reset the security token

* Sign in to Salesforce **as the integration user**.
* Navigate to the user's personal settings and select **Reset My Security
  Token** (under **My Personal Information**, or search "Reset Security
  Token" in Setup's Quick Find if using Salesforce's newer Setup UI).
* Salesforce emails the new token to the user's registered email address —
  copy it from there.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Username | `username` | `SALESFORCE_USERNAME` |
| Password | `password` | `SALESFORCE_PASSWORD` |
| Security Token | `token` | `SALESFORCE_TOKEN` |

`domain` (`SALESFORCE_DOMAIN`) is optional — set it if the org logs in
through a custom "My Domain" host rather than Salesforce's default login
host.

**Caveat:** if the integration user's login is IP-restricted (login IP
ranges on the profile), the **Reset My Security Token** option may not
appear — either add the collector's outbound IP to the profile's allowed
ranges, or remove IP restrictions for this specific integration user, per
your org's security policy.
