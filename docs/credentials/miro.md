# Miro — credential setup

[← back to collector docs](../collectors/miro.md)

Miro's REST API has **no client-credentials grant** — there is no way to
turn an app's client id/secret into a token on their own. Every call needs
an OAuth 2.0 **access token** tied to a user who has authorised the app.
For an unattended collector the practical path is Miro's "install the app
into your own team and copy the token" flow, which skips the redirect
dance.

The resources this collector reads split by plan:

| Resource | Plan | Scope required |
| --- | --- | --- |
| `boards`, `board_members` | any | `boards:read` |
| `org_members` | Enterprise, Company Admin | `organizations:read` |
| `teams`, `team_members` | Enterprise, Company Admin | `organizations:teams:read` |
| `audit_logs` | Enterprise, Company Admin | `auditlogs:read` |
| `board_classifications` | Enterprise + Data Classification add-on, Company Admin | `boards:read` |

On a non-Enterprise plan (or with a token missing a scope) the five
org-scoped resources return a clear `403` naming the missing scope;
`boards` and `board_members` still work.

## Create the app and token

1. Go to <https://miro.com/app/settings/user-profile/apps/> (or **Your
   Miro apps** from the developer docs) and **Create new app**. Name it
   e.g. `CCM - Read Only`. Tie it to the team you want to collect from.
2. In the app's settings, under **Permissions / Scopes**, tick only the
   read scopes you need from the table above:
   * always: `boards:read`, `identity:read`, `team:read`
   * Enterprise, add: `organizations:read`, `organizations:teams:read`,
     `auditlogs:read`
3. Under **App Credentials / Redirect URI**, leave the redirect URI as the
   default (`http://localhost` is fine — it is not used by the copy-token
   flow).
4. **Token expiration**: if the app offers an "Expire user authorization
   token / use refresh tokens" toggle, leave it **off** so the copied
   token does not expire. (This collector takes a static token and does
   not implement refresh.)
5. Scroll to **Install app and get OAuth token**, click it, pick the team,
   and authorise. Miro shows an **access token** — copy it.

## Enterprise: install org-wide

The org-scoped endpoints (`org_members`, `teams`, `team_members`,
`audit_logs`, `board_classifications`) only work when a **Company Admin**
has installed the app for the whole organization, not just one team:

* A Company Admin opens **Company admin → Apps** (or **Company settings →
  Apps & integrations**), finds the app, and installs / approves it for
  the organization.
* The token is then generated (step 5 above) while signed in as that
  Company Admin, so it inherits the admin's org-wide read access.

Miro also runs an Enterprise API early-access programme; if the org-scoped
endpoints 404 rather than 403, request access via the form linked from
Miro's API reference.

## Self-hosted / regional base URL

`base_url` (config key) / `MIRO_BASE_URL` (env var) overrides the API host;
it defaults to `https://api.miro.com` and normally does not need setting.

## Record the credentials

| Value | Config key | Environment variable |
| --- | --- | --- |
| OAuth access token | `access_token` | `MIRO_ACCESS_TOKEN` |
| API base URL (rarely needed) | `base_url` | `MIRO_BASE_URL` |

`MIRO_CLIENT_ID` / `MIRO_CLIENT_SECRET` are not used by this collector.
