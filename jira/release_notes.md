#### The following enhancements have been made to the Jira connector in version 3.0.0:

- Added support for **Jira Server / Data Center (on-premise)** alongside the existing **Jira Cloud** support. A single `Authentication Type` configuration picklist now drives both the credential type and the underlying Jira REST API surface:
    - `Cloud (Email + API Token)` — `/rest/api/3/` with Atlassian Document Format (existing behavior).
    - `Server / Data Center (Personal Access Token)` — `/rest/api/2/`, sent as `Authorization: Bearer <PAT>`. Requires Jira Server 8.14+.
    - `Server / Data Center (Username + Password)` — `/rest/api/2/` with HTTP Basic auth.
- All endpoint paths now resolve through the selected REST version. Cloud-only payload constructs (Atlassian Document Format for `description` and comments) are sent only on Cloud; Server / Data Center receives plain-text bodies.
- The `Search Users` action now uses the correct endpoint per deployment: `/rest/api/3/users/search` on Cloud, `/rest/api/2/user/search` on Server / DC.
- The `Parse JQL` action now raises a clear error on Server / DC, where the `/jql/parse` endpoint does not exist (Cloud-only).
- Removed an HMAC-style edge case in the request signer that previously included query strings when computing per-request signatures.

#### Breaking changes

- Existing Cloud configurations are migrated automatically: `Authentication Type` defaults to `Cloud (Email + API Token)`, preserving the prior behavior with the existing `Username` and `API Token` values.
