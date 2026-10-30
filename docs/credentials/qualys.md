# Qualys — credential setup

[← back to collector docs](../collectors/qualys.md)

These steps create a dedicated, read-only API user for the CCM integration.
One user and one set of `QUALYS_*` credentials cover every Qualys table:
VMDR, Policy Compliance, TotalAppSec and Global AssetView / CSAM. Create the
user, then grant access to each module you want collected. A table whose
module the user (or the subscription) has no access to fails on its own; the
other tables still collect.

Menu labels vary between Qualys releases, so the exact wording on your
subscription may differ.

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

| Tables | Module | API | Access comes from |
| --- | --- | --- | --- |
| `vm_hosts`, `vm_knowledgebase`, `vm_detections` | VMDR | `/api/{4,5}.0/fo/...` on the API server | Reader role and asset groups ([below](#create-the-user-account)) |
| `compliance_policies`, `compliance_policy_controls`, `compliance_posture` | Policy Compliance | `/api/{2,4}.0/fo/compliance/...` on the API server | Reader role and asset groups ([below](#policy-compliance)) |
| `webapps`, `webapps_findings` | TotalAppSec (WAS) | `/qps/rest/3.0/search/was/...` on the API server | Role and tag scope ([below](#totalappsec)) |
| `assets`, `assets_software`, `assets_open_ports` | Global AssetView / CSAM | `/rest/2.0/search/am/asset` on the gateway | Role and tag scope ([below](#global-assetview--csam)) |

The **Reader** role can call every VMDR API, but only returns hosts in the
asset groups assigned to the user. A Reader with no asset groups
authenticates fine and returns empty tables, with no error to say so.
Getting the scope right is the step most often missed.

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
* **Security**: leave two-factor authentication (VIP or SecureID) and
  **SAML SSO** unticked. The collector uses HTTP Basic authentication, which
  none of them supports. If
  your subscription enforces SSO for all users, ask your Qualys administrator
  to exempt this account.
* Select **Save**.

Qualys generates the **username** itself (usually a company prefix plus
letters from the name, e.g. `acme_cr`); you cannot choose it. It is shown in
the user list and in the activation email.

## Activate the account

A new account cannot make API calls until it has completed its first login
and accepted the Qualys EULA. Until then every request fails with code
`2003` (see [Troubleshooting](#troubleshooting)).

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

## Grant module access

Each section below is only needed for the tables you want collected.

### Policy Compliance

* **Subscription**: posture info requires Policy Compliance (or SCA) with
  the API add-on. Without it, the compliance tables fail and the others are
  unaffected.
* In the **Users** module, edit the `CCM Read Only` user.
* **User Role**: keep `Reader` with **API** ticked. Make sure the user has
  access to the **Policy Compliance** module (on subscriptions with both VM
  and PC, the user role page lists the modules the user can use).
* **Asset Groups**: make sure the assigned asset groups include every host
  your compliance policies evaluate. PC hosts are often in separate asset
  groups from VM hosts, so a user set up only for VMDR can miss them. Every
  compliance policy is listed regardless of scope, but posture rows are only
  returned for hosts in the user's asset groups.
* **Permissions**: some releases hide compliance hosts from Readers unless
  **Manage compliance** is ticked. If policies are listed but posture is
  empty for hosts you know are in scope, tick it.
* Select **Save**.

### TotalAppSec

TotalAppSec (Web Application Scanning) does not use VMDR asset groups:
access comes from a **role** with the **API Access** permission, and
visibility from the user's **tag scope**. A web application is only visible
when one of its tags matches one of the user's scope tags.
Subscription-level OAuth clients cannot be used: Qualys does not accept them
on any Web Application Scanning endpoint.

You need a Manager, or a user with the Edit User permission.

* Open the **Administration** module and go to **Role Management**.
* Check whether the built-in **WAS Reader** role (or **TAS Reader**,
  depending on release) includes **API Access** under **Access
  Permissions**. If it does, use it. If not, select **Create Role**, name it
  e.g. `CCM WAS Reader`, and grant:
    * **Access Permissions**: **API Access** and **WAS** (TotalAppSec)
      module access.
    * **Web Application Permissions**: view only. Leave create, edit,
      delete, scan and purge unticked.
* Select **Save**.
* In **Administration** > **User Management**, edit the `CCM Read Only`
  user, add the WAS reader role, and under **Scope** give the user every web
  application the collection should cover, typically **Full Scope**. If you
  scope by tags instead, an application with none of those tags is
  invisible to the collector, with no error to say so.
* Select **Save**.

Create a new role rather than adding **API Access** to the built-in one if
other users have it: editing a shared role changes the permissions of every
user who has it.

### Global AssetView / CSAM

The asset tables authenticate against the subscription's gateway
(`POST /auth`) and call the asset search API. Global AssetView / CSAM does
not use VMDR asset groups: access comes from a **role** that grants API and
read permissions, and visibility from the user's **tag scope**.

* Open the **Administration** module and go to **Role Management**.
* Select **Create Role** and name it, e.g. `CCM Asset Reader`. Grant only:
    * **Access Permissions**: **API Access**.
    * **CSAM** (or **Global AssetView**) module: **Module Access** and the
      asset **read/view** permissions.
    * **Asset Management**: read/view assets. Leave create, edit, delete and
      tag management unticked.
* Select **Save**.
* In **Administration** > **User Management**, edit the `CCM Read Only`
  user, add the `CCM Asset Reader` role, and under **Scope** give the user
  every asset the collection should cover, typically **Full Scope**.
* Select **Save**.

Qualys doesn't state whether the free Global AssetView tier includes this
API or only paid CSAM; if authentication succeeds but the asset search is
refused, check the subscription's entitlement.

## Find the API server URL

The API server depends on the platform your subscription is hosted on. To
find it in the portal, open **Help** > **About** and look under **Qualys
Scanner Appliances** > **Security Operations Center (SOC)**: the host
starting `qualysapi.` is the API server (e.g.
`qualysapi.qg1.apps.qualys.com.au:443`; drop the `:443`). The page has no
separate "API server" label, and does not list the gateway. You can also
match the portal address you log in to against this table.

The asset tables use the gateway. It is derived from the API server for
every platform below, so you only need to set it (`QUALYS_GATEWAY_URL`) if
your subscription is on a private cloud platform whose API server doesn't
start `qualysapi.`:

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
but use the `qualysapi.` host from **Help** > **About** or the table above.

## Troubleshooting

A table fails on the first account-level error rather than retrying,
since retrying the same credentials cannot succeed and every failed attempt
counts towards Qualys's failed-login lockout. When the error rejects the user
itself (`2000`, `2002`, `2003`, `2011`, or a 401 from the gateway login), the
collector also sends no further requests in that run: every later Qualys
table fails at once with "already rejected these credentials" and the
original error, so one bad password costs one failed login, not one per
table. `2012` refuses only that API, so the other tables still collect.

The error carries Qualys's own code and text, which map to these causes
(from Qualys's API error table):

| HTTP | Code | Qualys text | Usual cause |
| --- | --- | --- | --- |
| 401 | `2000` | Bad Login/Password | Wrong username or password, **API** not ticked for the user, or no API on the subscription (Community Edition) |
| 403 | `2002` | User account is inactive | The account has been deactivated |
| 403 | `2012` | User license is not authorized to run this API | The subscription's licence does not include this API |
| 409 | `2003` | Registration must be completed before API requests will be served | The account has not completed its first login and EULA |
| 409 | `2011` | SecureID authentication is required for this account | SecureID is enabled on the account, which blocks the API |

`2000` with a username and password that work in the portal almost always
means the API is not enabled, for the user or for the subscription.

## Record the credentials

Store the following values securely. These map directly to the collector's
config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| API server URL (e.g. `https://qualysapi.qualys.com`) | `base_url` | `QUALYS_BASE_URL` |
| Username (generated by Qualys) | `username` | `QUALYS_USERNAME` |
| Password (set at first login) | `password` | `QUALYS_PASSWORD` |
| Gateway URL, only if it can't be derived (see above) | `gateway_url` | `QUALYS_GATEWAY_URL` |
