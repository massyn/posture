# Qualys — credential setup

[← back to collector docs](../collectors/qualys.md)

These steps create a dedicated, read-only API user for the CCM integration.
The other Qualys collectors ([Policy Compliance](qualys_compliance.md),
[Global AssetView](qualys_gav.md), [TotalAppSec](qualys_tas.md)) reuse this
user and add their own module access on top, so start here even if you only
need one of them.

**Unverified:** these steps follow Qualys's public documentation and have
not been checked against a live subscription. Menu labels vary between
Qualys releases, so verify each step on your own subscription.

## Check the subscription has API access

API access is a subscription feature, not just a user setting. **Qualys
Community Edition** (the free tier, shown as "Community Edition" next to the
Qualys logo in the portal) has no API access, and some paid subscriptions
don't include it either. On a subscription without the API, every API call
fails with HTTP 401 and code `2000 Bad Login/Password`, even with a username
and password that log in to the portal fine. No user, role or config change
fixes it.

Community Edition also has a single user and no **Users** module, so the
steps below cannot be followed there. If you are unsure whether your
subscription has the API, ask Qualys support or your account manager before
creating the user.

## What the collector needs

The collector calls three VMDR APIs: host list (`/api/5.0/fo/asset/host/`),
KnowledgeBase (`/api/4.0/fo/knowledge_base/vuln/`) and host list detection
(`/api/5.0/fo/asset/host/vm/detection/`). The **Reader** role can call all
three, but only returns hosts in the asset groups assigned to the user. A
Reader with no asset groups authenticates fine and returns empty tables,
with no error to say so. Getting the scope right is the step most often
missed.

## Create the user account

You need a Manager (or a user with the User Administrator role).

* Log in to the Qualys portal and open the **Users** (User Management)
  module, then select **Create User** > **Create Reader User** (older
  releases: **Users** > **New** > **User**).
* **General Information**: Qualys requires every one of these, even for a
  service account:
    * **First name**: `CCM`
    * **Last name**: `Read Only`
    * **Title**: e.g. `Service account`
    * **Phone**
    * **Email**: a mailbox you control. The activation email goes here, and
      the account cannot be used until it is activated (below).
    * **Address 1** and **Country**
* **Locale**: leave the defaults, or set your time zone.
* **User Role**:
    * **User Role**: `Reader`.
    * **Allow access to**: tick **API**. Tick **GUI** too if you want to
      complete activation in the browser; you can untick it afterwards.
    * **Business Unit**: leave as **Unassigned** unless the collection should
      only cover one business unit. A user inside a business unit can only be
      given that unit's asset groups, and sees only those hosts.
* **Asset Groups**: assign every asset group the collection should cover.
  To cover the whole subscription, assign the **All** asset group (if your
  subscription does not let you assign it, assign every asset group
  instead). New asset groups created later are not added automatically.
* **Permissions**: leave every management permission unticked. The
  collector only reads.
* **Security**: leave two-factor authentication and **SAML SSO** unticked.
  The collector uses HTTP Basic authentication, which neither supports. If
  your subscription enforces SSO for all users, ask your Qualys administrator
  to exempt this account.
* Select **Save**.

Qualys generates the **username** itself (usually a company prefix plus
letters from the name, e.g. `acme_cr`); you cannot choose it. It is shown in
the user list and in the activation email.

## Activate the account

A new account cannot make API calls until it has completed its first login
and accepted the Qualys EULA. Until then Qualys answers every request with
HTTP 409 and code `2003` ("Registration must be completed before API
requests will be served"), which the collector reports as an
`AuthenticationError`. Code `2000 Bad Login/Password` is a different
problem: wrong credentials, API access not ticked, or no API on the
subscription (see above).

* Open the **Registration** email sent to the address above and follow the
  link to retrieve the username and initial password. The link works once
  only; if it has expired, use **Forgot password** on the login page.
* Log in to the portal as the new user, accept the EULA, and set a new strong
  password when prompted. Store it securely.
* If you created the user without GUI access, complete the first login with
  Qualys's `acceptEULA.php` API call instead.
* Optionally edit the user again and untick **GUI** so the account is API
  only.

Check your subscription's password policy (**Users** > **Setup** >
**Security**): if passwords expire, the collector stops authenticating when
this one does.

## Find the API server URL

The API server depends on the platform your subscription is hosted on. It
is listed under **Help** > **About** in the portal (**Qualys API Server**).
You can also match the portal address you log in to against this table; the
gateway column is for the [Global AssetView collector](qualys_gav.md):

| Platform | API server (`base_url`) | Gateway (`gateway_url`) |
| --- | --- | --- |
| US 1 | `https://qualysapi.qualys.com` | `https://gateway.qg1.apps.qualys.com` |
| US 2 | `https://qualysapi.qg2.apps.qualys.com` | `https://gateway.qg2.apps.qualys.com` |
| US 3 | `https://qualysapi.qg3.apps.qualys.com` | `https://gateway.qg3.apps.qualys.com` |
| US 4 | `https://qualysapi.qg4.apps.qualys.com` | `https://gateway.qg4.apps.qualys.com` |
| EU 1 | `https://qualysapi.qualys.eu` | `https://gateway.qg1.apps.qualys.eu` |
| EU 2 | `https://qualysapi.qg2.apps.qualys.eu` | `https://gateway.qg2.apps.qualys.eu` |
| EU 3 | `https://qualysapi.qg3.apps.qualys.it` | `https://gateway.qg3.apps.qualys.it` |
| India | `https://qualysapi.qg1.apps.qualys.in` | `https://gateway.qg1.apps.qualys.in` |
| Canada | `https://qualysapi.qg1.apps.qualys.ca` | `https://gateway.qg1.apps.qualys.ca` |
| UAE | `https://qualysapi.qg1.apps.qualys.ae` | `https://gateway.qg1.apps.qualys.ae` |
| UK | `https://qualysapi.qg1.apps.qualys.co.uk` | `https://gateway.qg1.apps.qualys.co.uk` |
| Australia | `https://qualysapi.qg1.apps.qualys.com.au` | `https://gateway.qg1.apps.qualys.com.au` |
| KSA | `https://qualysapi.qg1.apps.qualysksa.com` | `https://gateway.qg1.apps.qualysksa.com` |

On some platforms the portal host (`qualysguard...`) answers API calls too,
but use the API server from **Help** > **About** or the table above.

## Record the credentials

Store the following values securely. These map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| API server URL (e.g. `https://qualysapi.qualys.com`) | `base_url` | `QUALYS_BASE_URL` |
| Username (generated by Qualys) | `username` | `QUALYS_USERNAME` |
| Password (set at first login) | `password` | `QUALYS_PASSWORD` |
