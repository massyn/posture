# OWASP Dependency-Track: credential setup

[← back to collector docs](../collectors/dependency_track.md)

These steps create a dedicated, read-only team and API key for the CCM
integration. Dependency-Track API keys belong to a team and carry exactly
that team's permissions, so the key is only as privileged as the team you
create for it.

## Create the read-only team

* Log in to Dependency-Track as an administrator.
* Go to **Administration** > **Access Management** > **Teams**.
* Select **Create Team** and name it `CCM - Read Only`.
* Open the new team and add only these permissions:
  * `VIEW_PORTFOLIO` for projects and their components
  * `VIEW_VULNERABILITY` for project findings
* If **Portfolio Access Control** is enabled on your server
  (**Administration** > **Configuration** > **Access**), also assign the
  projects the team may see. Projects not assigned to the team are left out
  of the collection without any error.

## Generate the API key

* In the same team view, under **API Keys**, select **+** to generate a key.
* Copy the key value. Newer servers show it in full only once.

Note the API server's base URL: the host that serves `/api/v1`, which is
not always the same host as the web front end.

## Record the credentials

Store the following values securely: they map directly to the collector's
config:

| Value | Config key | Environment variable |
| --- | --- | --- |
| Team API key | `api_key` | `DEPENDENCY_TRACK_API_KEY` |
| API server base URL (e.g. `https://dtrack-api.example.com`) | `endpoint` | `DEPENDENCY_TRACK_ENDPOINT` |

Give `endpoint` without the `/api/v1` suffix; the collector adds it.
