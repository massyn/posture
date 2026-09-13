# Trello — credential setup

[← back to collector docs](../collectors/trello.md)

Trello authenticates with a per-account API key plus a token that inherits
whatever access the authorizing user has to their boards — there is no
separate read-only role to assign, so scope this to a dedicated account
with access to only the boards you want collected, rather than a personal
admin account.

## Get the API key

* Log in to Trello as the account you want the integration to run as.
* Go to <https://trello.com/power-ups/admin> and create (or select) a
  Power-Up/App — this is what Trello's API key is scoped to.
* Under the app's **API key** tab, copy the key value.

## Generate the token

* From the same API key page, follow the **Token** link (or visit
  `https://trello.com/1/authorize?expiration=never&scope=read&response_type=token&name=CCM&key={API_KEY}`,
  substituting your key) and authorize with **read**-only scope.
* Copy the token value once it's issued.

## Record the credentials

Store the following values securely — these map directly to the collector's
required config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| API Key | `api_key` | `TRELLO_API_KEY` |
| Token | `token` | `TRELLO_TOKEN` |

`board` (`TRELLO_BOARD`) is optional — set it to a board id to default
`cards` collection to that single board instead of every board the
account can see.

**Caveat:** the token's access is exactly the authorizing account's board
access — Trello has no admin console equivalent to Okta's Read Only
Administrator role, so least-privilege here means choosing which boards the
authorizing account belongs to, not a token permission you configure
separately.
