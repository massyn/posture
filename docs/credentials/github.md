# GitHub — credential setup

[← back to collector docs](../collectors/github.md)

This collector authenticates with a GitHub **fine-grained personal access
token** scoped read-only to the organizations it needs to see — PAT auth
only (no GitHub App/JWT path). A token must be created by a member of each
target organization (ideally a dedicated low-privilege bot/service
account, not a personal admin identity) and, depending on the
organization's PAT policy, approved by an organization owner.

## Create the token

* Sign in to GitHub as the account that will own the token (ideally a
  dedicated `ccm-readonly` service account, or a personal account with
  organization membership if the org requires that).
* Go to **Settings** > **Developer settings** > **Personal access tokens**
  > **Fine-grained tokens**.
* Select **Generate new token**.
* Fill in the following fields:
    * **Token name**: `CCM - Read Only`
    * **Expiration**: set an appropriate expiry and calendar a renewal
    * **Resource owner**: the organization this token should read
    * **Repository access**: **All repositories** (or the specific subset
      this integration needs) — a fine-grained token cannot span multiple
      organizations, so create one token per organization if collecting
      across several
* Under **Repository permissions**, set the following to **Read-only**:
    * **Metadata** (required baseline for any repository access)
    * **Contents** — needed for `branches`/`branch_protection_rules`
    * **Code scanning alerts** — needed for `code_scanning_alerts`
    * **Dependabot alerts** — needed for `dependabot_alerts`
* Under **Organization permissions**, set the following to **Read-only**:
    * **Members** — needed for `members`
* Select **Generate token**.
* If the organization requires approval for fine-grained tokens, an
  organization owner must approve it (**Settings** > **Personal access
  tokens** > **Pending requests**) before it will work.
* Copy the token value immediately — it is only shown once.

**Caveat:** GitHub's fine-grained PAT permission set has evolved since
introduction and a handful of endpoints (some enterprise-level Dependabot
routes) still require a classic PAT or OAuth app rather than a fine-grained
token — if a resource 404s or 403s with an otherwise-correctly-scoped
fine-grained token, check GitHub's current fine-grained PAT documentation
for that specific endpoint before assuming a permissions gap.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Personal access token | `token` | `GITHUB_TOKEN` |

### Optional

| Value | Config key | Environment variable |
| --- | --- | --- |
| API base URL (only for GitHub Enterprise Server; defaults to `api.github.com`) | `endpoint` | `GITHUB_ENDPOINT` |
