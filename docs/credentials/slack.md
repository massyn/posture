# Slack — credential setup

[← back to collector docs](../collectors/slack.md)

This collector targets Slack's **org-level admin API** (Enterprise Grid),
which needs an org-level, admin-scoped token — not a regular per-workspace
bot token. Whichever token tier you provide, it is used as-is; there is no
fallback logic in the collector.

## Token tiers — read this first

* **Org-level admin token (recommended, full data)** — created from an
  Enterprise Grid **org-level app** installed by an **Org Owner/Admin**,
  with the admin scopes below. Every resource this collector offers
  (`users`, `channels`, `channel_members`, `user_groups`, `apps`) works.
* **Regular workspace bot token (thinner data, still usable)** — if your
  org isn't on Enterprise Grid, or you'd rather not provision an org-level
  app, a normal `xoxb-...` bot token still works for `channel_members` and
  `user_groups` (plain Conversations/usergroups scopes). `users` and `apps`
  need the `admin.*` API family, which a workspace token cannot call:
  those two resources fail with a Slack `missing_scope`/`not_allowed_token_type`
  error, which posture surfaces as `IncompleteCollection` for just that
  resource — `ccm.collect("users")` raises, but
  `ccm.collect("channel_members")` on the same collector instance still
  succeeds. There is no way to get `users`/`apps` data without an org-level
  admin token.

## Create the org-level app and token (full data)

* Go to <https://api.slack.com/apps> while signed in as an **Org
  Owner/Admin**, and create a new app.
* Under **OAuth & Permissions**, add these **User Token Scopes**:
  * `admin.users:read` — for `users`
  * `admin.conversations:read` — for `channels`
  * `channels:read`, `groups:read` — for `channel_members` (public and
    private channels respectively)
  * `usergroups:read` — for `user_groups`
  * `admin.apps:read` — for `apps`
* Install the app to your organization (not just a single workspace) —
  Slack prompts for org-level install when the app requests an `admin.*`
  scope and is authorized by an Org Owner/Admin.
* Copy the **User OAuth Token** (`xoxp-...`) from **OAuth & Permissions**
  after install.

## Regular workspace bot token (thinner data)

* Go to <https://api.slack.com/apps>, create (or reuse) an app, and add the
  **Bot Token Scopes** `channels:read`, `groups:read`, and
  `usergroups:read`.
* Install the app to your workspace and copy the **Bot User OAuth Token**
  (`xoxb-...`).
* `users` and `apps` will fail per the token tiers note above; the rest of
  the collector still works.

## Record the credentials

Store the following value securely — it maps directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| OAuth token (`xoxp-...` org-level, or `xoxb-...` workspace) | `token` | `SLACK_TOKEN` |
