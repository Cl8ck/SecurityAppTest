# SafeVault

SafeVault is a local .NET 10 practice application for learning authentication, authorization, and secure user management. It uses a Blazor WebAssembly client, an ASP.NET Core server, ASP.NET Core Identity, and a local SQLite database. No cloud database is required.

## How the application works

1. The server starts and opens the SQLite database at `SafeVaultApp.Server\App_Data\safevault.db`. On first run it creates the Identity tables and the `User` and `Admin` roles.
2. Registration creates an Identity account with a securely hashed password, assigns the `User` role, and signs the new account in.
3. Login verifies the password through Identity and issues an HTTP-only, SameSite Strict authentication cookie.
4. The Blazor client checks `GET /api/auth/me` to obtain the signed-in user's name and roles. A signed-out visitor is redirected to `/login`.
5. Home and Users pages require the `User` role. The Admin page and its management API require the `Admin` role. API authorization is enforced on the server; hiding a tab in the client is not the security boundary.
6. The Admin page can list users and their roles, create `User` or `Admin` accounts, and change roles. Role changes update the user's security stamp. The server validates security stamps on every authenticated request so an existing cookie cannot continue to use stale role claims. The last Admin cannot be changed to `User`.

## Project layout

| Project or path | Purpose |
| --- | --- |
| `SafeVaultApp` | Blazor WebAssembly UI: login, registration, protected Home, Users, and Admin pages. |
| `SafeVaultApp.Server` | ASP.NET Core host, authentication and user-management APIs, Identity configuration, and SQLite database. Serves the client and API together. |
| `SafeVaultApp.Tests` | Integration tests for authentication, authorization, role management, and cookie invalidation. |
| `SafeVaultApp.Server\App_Data` | Local SQLite database directory; generated at runtime and excluded from source control. |

## Run the application

From the repository root, start the server:

```powershell
dotnet run --project SafeVaultApp.Server\SafeVaultApp.Server.csproj
```

Open <http://localhost:5259>. This server-hosted setup is the recommended way to run the application: one process serves both the UI and API.

The standalone WebAssembly client is optional. Its development profile uses port `5260` (HTTPS `7150`) and sends API requests to the server on port `5259` (HTTPS `7149`). If you run the client separately, keep both projects running. Do not start both projects on the same port.

## Local administrator account

Default Admin credentials are username:AdminTest passrword:Admin@password1
To create or promote the local test administrator, set both bootstrap settings in the same PowerShell terminal before starting the server:

```powershell
$env:SafeVault__AdminUsername = "AdminTest"
$env:SafeVault__AdminPassword = Read-Host "Enter the local AdminTest password"
dotnet run --project SafeVaultApp.Server\SafeVaultApp.Server.csproj
```

When prompted, enter the practice password provided for your local environment. The prompt keeps it out of the README and source control. The password must satisfy the configured Identity policy: at least 12 characters with uppercase, lowercase, a number, and a non-alphanumeric character. The bootstrap settings are used at server startup; leave them unset when they are not needed. Never put real or reusable credentials in source files or commit history.

## Authentication and management API

All JSON endpoints use the local Identity database and the authentication cookie where authorization is required.

| Method | Route | Access | Purpose |
| --- | --- | --- | --- |
| `POST` | `/api/auth/register` | Anonymous | Register a regular `User` and sign in. |
| `POST` | `/api/auth/login` | Anonymous | Verify credentials and sign in. |
| `POST` | `/api/auth/logout` | Signed in | Sign out and clear the cookie. |
| `GET` | `/api/auth/me` | Signed in | Return the current account name and roles. |
| `GET` | `/api/admin` | `Admin` | Verify access to an administrator-only resource. |
| `GET` | `/api/admin/users` | `Admin` | List registered accounts and their roles. |
| `GET` | `/api/admin/users/{id}` | `Admin` | Get one registered account and its roles. |
| `POST` | `/api/admin/users` | `Admin` | Create an account with the selected `User` or `Admin` role. |
| `PUT` | `/api/admin/users/{id}/role` | `Admin` | Change an account's role. The last administrator cannot be demoted. |

Registration requires a unique email, a 3-64 character username using letters, digits, `_`, `-`, or `.`, and a password meeting the policy above. Duplicate accounts return a conflict; invalid input returns validation details. OpenAPI is available at `/openapi/v1.json` in Development. Example API requests are in `SafeVaultApp.Server\SafeVaultApp.Server.http`.

## Run the tests

From the repository root:

```powershell
dotnet test SafeVaultApp.Tests\SafeVaultApp.Tests.csproj
```

The integration tests use temporary SQLite databases. They cover registration and login, invalid credentials, anonymous and regular-user access denial, Admin user creation and role changes, last-Admin protection, cross-origin client requests, and rejection of a demoted administrator's existing cookie.

## Copilot-assisted development and review

Copilot was used to help scaffold the Blazor login experience, Identity and SQLite integration, role-protected pages, user-management endpoints, and integration tests. The implementation is organized so the UI, API endpoints, and Identity service layer can be reviewed separately.

For a useful Copilot-assisted change or GitHub review:

1. State the intended behavior and the authorization boundary (which role can perform which action).
2. Ask Copilot to trace the behavior through the UI, server endpoint, service, and tests before proposing a code change.
3. Keep authentication and authorization decisions on the server; have Copilot add a test for both allowed and denied access.
4. Ask Copilot to run the focused test project and build, and inspect the diff and any security-sensitive changes before merging.
5. Do not provide real credentials, secrets, or production data in Copilot prompts or commit them to the repository.

Suggested review prompt:

> Trace the Admin user-role update from the Blazor UI through the API and Identity service. Verify that non-admin users cannot call it, the last Admin cannot be demoted, and an already-issued cookie loses Admin access immediately after a role change. Run the relevant integration tests and report any missing cases without exposing credentials.
