# Tenable.sc — credential setup

[← back to collector docs](../collectors/tenablesc.md)

Tenable.sc (Security Center) is self-hosted — unlike Tenable.io, there is
no shared cloud host, so you'll need your own instance's URL. API key
authentication must also be enabled instance-wide before it can be used.
This collector scopes `hosts`/`asset_ips` to a single named asset list
(`"Non Crowdstrike Assets"` by default, since CrowdStrike-covered hosts are
already collected separately) — the account below only needs read access to
that list plus vulnerability data, not the whole instance.

## Enable API key authentication (instance-wide, one-time)

* Log in to Tenable.sc as an administrator.
* Navigate to **System** > **Configuration** > **API Keys** (naming may
  vary slightly by version) and enable API key authentication for the
  instance if it isn't already.

## Create the user account

* Navigate to **Users** > **Users** and create a new user (e.g.
  `ccm-readonly`).
* Assign a role with read-only access to the vulnerability/asset data this
  collector needs — Tenable.sc's **Security Manager** role is the closest
  built-in fit if your instance doesn't have a narrower custom read-only
  role; avoid Administrator.
* Ensure the user has visibility into the asset list this collector targets
  (`"Non Crowdstrike Assets"` by default, or whatever `asset_name` you
  configure).

## Generate the API keys

* An administrator can generate API keys for any user; other roles can
  generate keys for accounts of the same role — so either an admin
  generates them for the new user, or you sign in as that user directly.
* Navigate to the user's **API Keys** management (**My Account** > **API
  Keys** when signed in as the user, or the equivalent admin-side user
  management screen).
* Generate a new key pair and copy the **Access Key** and **Secret Key**
  immediately — Tenable.sc only displays them once.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Tenable.sc URL (e.g. `https://tenablesc.yourdomain.com`) | `endpoint` | `TENABLESC_ENDPOINT` |
| Access Key | `access_key` | `TENABLESC_ACCESS_KEY` |
| Secret Key | `secret_key` | `TENABLESC_SECRET_KEY` |

**Caveat:** exact menu paths (System Configuration, API Key management)
vary by Tenable.sc version — confirm current navigation against your own
instance's admin guide if the above doesn't match what you see.
