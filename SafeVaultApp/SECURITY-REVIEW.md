# SafeVault Authentication and Authorization Review

**Date:** 2026-10-23  
**Scope:** Local SafeVaultApp authentication, role authorization, and administrator user-management endpoints.

## Summary

One medium-severity authorization issue was identified and fixed: an administrator whose role had been changed could keep using an existing authentication cookie with the old `Admin` role claim until security-stamp validation ran.

## Finding

### SV-01 — Demoted administrator may retain admin access until cookie revalidation

- **Severity:** Medium
- **Confidence:** 8/10
- **Affected code:** [`UserManagementService.cs`](./SafeVaultApp.Server/Services/UserManagementService.cs), role-change flow; administrator routes are protected in [`AdminUserEndpoints.cs`](./SafeVaultApp.Server/Endpoints/AdminUserEndpoints.cs).
- **Resolution:** Identity security-stamp validation is configured to run on every authenticated request. Role changes update the affected account's security stamp, so an existing cookie with stale role claims is rejected on its next request.
- **Regression test:** `DemotedAdministratorLosesAccessOnTheirNextRequest` signs in a second administrator, demotes that account, then verifies its existing cookie no longer grants access.
- **Trade-off:** This causes a database security-stamp check for every authenticated request. Reassess the validation interval if the app's scale or traffic profile changes.

## Validation

Run `dotnet test SafeVaultApp.Tests\SafeVaultApp.Tests.csproj` to verify registration, authentication, role-based access, admin management, and immediate cookie invalidation after role changes.

No external targets, brute-force attempts, destructive actions, or production data were involved in this review.
