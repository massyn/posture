# HCL BigFix — credential setup

[← back to collector docs](../collectors/bigfix.md)

These steps create a dedicated, non-master console operator for the CCM
integration. BigFix has no read-only API key: the collector authenticates
over HTTP Basic as a console operator, and every query it runs returns only
what that operator can see. Restricting the operator's *permissions* keeps it
read-only; giving it full *visibility* keeps the snapshot complete.

**Unverified:** these steps follow HCL's public BigFix Platform
documentation and have not been checked against a live console. Menu labels
vary between BigFix versions — verify each step on your own deployment.

## Create the operator

* Log in to the BigFix Console as a Master Operator.
* Go to **BigFix Management** > **Operators**.
* Right-click in the operator list and select **Create Local Operator**
  (or **Add LDAP Operator** to use a directory service account instead).
* Name it `CCM - Read Only` and set a strong password.
* On the operator's **Details** tab, set:
  * **Master Operator**: No
  * **Can use REST API**: Yes
  * **Can Create Actions**: No
  * **Custom Content**: No
  * **Can Lock**: No
  * **Can Submit Queries**: No
* On the **Administered Computers** tab (or via a **Role**), grant visibility
  of every computer the collection should cover — typically all computers.
  An operator scoped to a subset produces a snapshot of that subset only,
  with no error to say so.
* On the **Sites** tab, grant **Reader** access to every site whose Fixlets
  should appear in `fixlets` and `fixlet_results` (e.g. the patch and
  Enterprise Security sites).
* Save the changes.

## Prerequisites on the server

* `/api/query` evaluates Session Relevance through BigFix Explorer when one
  is deployed, otherwise through Web Reports — at least one must be running.
* Note the root server's REST API base URL, including the port (default
  `52311`), e.g. `https://bigfix.example.com:52311`.
* If the root server presents a certificate signed by an internal CA, export
  that CA (and any intermediates) as a PEM bundle for `ca_bundle` below.
  If it presents a self-signed certificate you cannot obtain a CA for,
  `insecure` disables certificate verification altogether — this exposes the
  operator's password to anyone able to intercept the connection, so prefer
  `ca_bundle` wherever possible.

## Record the credentials

Store the following values securely — they map directly to the collector's
config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Root server base URL (with port) | `endpoint` | `BIGFIX_ENDPOINT` |
| Operator name | `username` | `BIGFIX_USERNAME` |
| Operator password | `password` | `BIGFIX_PASSWORD` |
| Path to a PEM CA bundle (optional) | `ca_bundle` | `BIGFIX_CA_BUNDLE` |
| Disable certificate verification (optional, `true`/`false`) | `insecure` | `BIGFIX_INSECURE` |

`ca_bundle` and `insecure` are mutually exclusive. With neither set, the
server's certificate is verified against the system's default trust store.
