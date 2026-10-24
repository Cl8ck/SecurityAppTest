using System.Security.Claims;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SafeVaultApp.Models;
using SafeVaultApp.Server.Services;

namespace SafeVaultApp.Server.Endpoints;

internal static class AuthEndpoints
{
    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/auth").WithTags("Authentication");

        group.MapPost("/register", async Task<Results<Created<AccountResponse>, ValidationProblem, Conflict<ProblemDetails>>> (
            RegisterRequest request,
            IAccountService accountService,
            CancellationToken cancellationToken) =>
        {
            var registration = await accountService.RegisterAsync(request, cancellationToken);
            if (registration.IdentityResult.Succeeded)
            {
                return TypedResults.Created("/api/auth/me", registration.Account!);
            }

            if (registration.IdentityResult.Errors.Any(error =>
                    error.Code is nameof(IdentityErrorDescriber.DuplicateUserName) or nameof(IdentityErrorDescriber.DuplicateEmail)))
            {
                return TypedResults.Conflict(new ProblemDetails
                {
                    Status = StatusCodes.Status409Conflict,
                    Title = "Account already exists",
                    Detail = "An account with that username or email already exists."
                });
            }

            var errors = registration.IdentityResult.Errors
                .GroupBy(error => string.IsNullOrWhiteSpace(error.Code) ? "registration" : error.Code)
                .ToDictionary(grouping => grouping.Key, grouping => grouping.Select(error => error.Description).ToArray());
            return TypedResults.ValidationProblem(errors);
        })
            .AllowAnonymous()
            .WithName("Register")
            .WithSummary("Register a local account")
            .WithDescription("Creates a user in the local SQLite database, assigns the User role, and signs in.")
            .Produces<AccountResponse>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status409Conflict);

        group.MapPost("/login", async Task<Results<Ok<AccountResponse>, UnauthorizedHttpResult>> (
            LoginRequest request,
            IAccountService accountService,
            CancellationToken cancellationToken) =>
        {
            var account = await accountService.LoginAsync(request, cancellationToken);
            return account is null ? TypedResults.Unauthorized() : TypedResults.Ok(account);
        })
            .AllowAnonymous()
            .WithName("Login")
            .WithSummary("Sign in to a local account")
            .WithDescription("Verifies the username and password, then issues a secure authentication cookie.")
            .Produces<AccountResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status401Unauthorized);

        group.MapPost("/logout", async Task<NoContent> (
            IAccountService accountService,
            CancellationToken cancellationToken) =>
        {
            await accountService.SignOutAsync(cancellationToken);
            return TypedResults.NoContent();
        })
            .RequireAuthorization()
            .WithName("Logout")
            .WithSummary("Sign out")
            .WithDescription("Clears the current authentication cookie.")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status401Unauthorized);

        group.MapGet("/me", (ClaimsPrincipal principal, CancellationToken cancellationToken) =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                return TypedResults.Ok(new AccountResponse(
                    principal.Identity?.Name ?? string.Empty,
                    principal.FindAll(ClaimTypes.Role).Select(claim => claim.Value).ToArray()));
            })
            .RequireAuthorization()
            .WithName("GetCurrentAccount")
            .WithSummary("Get the signed-in account")
            .WithDescription("Returns the current account name and assigned roles.")
            .Produces<AccountResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status401Unauthorized);

        return endpoints;
    }
}
