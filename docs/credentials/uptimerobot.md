# UptimeRobot — credential setup

[← back to collector docs](../collectors/uptimerobot.md)

UptimeRobot has no OAuth flow, no service-account concept, and no
per-scope API clients. Access is a single account-wide API key sent with
every request. UptimeRobot issues three kinds:

| Key type | Prefix | Access |
| --- | --- | --- |
| Main API key | `u` | Read **and write** to every monitor, alert contact, maintenance window, etc. on the account |
| Read-only API key | `ur` | Read-only access to the same data |
| Monitor-specific API key | `m` | Read-only, but scoped to a single monitor |

Use the **read-only API key** (`ur…`) for posture. It returns exactly the
same data this collector needs (`monitors`, `monitor_logs`,
`monitor_response_times`, `account`, `alert_contacts`) and cannot modify or
delete anything if the key leaks. A monitor-specific key is too narrow —
the collector enumerates every monitor on the account.

## Create the read-only API key

1. Sign in to UptimeRobot at <https://dashboard.uptimerobot.com> with an
   account that can see every monitor you want posture to collect. There is
   no separate "read-only user" to provision — the key type, not the user,
   is what constrains access. If you want an isolated identity, create a
   dedicated UptimeRobot account, invite it to the team / share the
   monitors with it, and generate the key from there.
2. Open **Settings** (left-hand navigation), then scroll to the **API**
   section (older layouts label this **My Settings → API Settings**, at the
   bottom of the page).
3. Next to **Read-Only API Key**, click **Create** (or **Show / hide it**
   if one already exists).
4. Copy the key. It starts with `ur` followed by the account number and a
   hyphenated suffix, e.g. `ur123456-abcdef0123456789abcdef01`.
5. Leave the **Main API Key** and any **Monitor-Specific API Keys**
   untouched — posture does not need them.

To revoke access later, return to the same screen and click **Delete** /
**Regenerate** on the read-only key; existing main and monitor-specific
keys are unaffected.

## Record the credentials

| Value | Config key | Environment variable |
| --- | --- | --- |
| Read-only API key | `token` | `UPTIME_ROBOT_TOKEN` |
