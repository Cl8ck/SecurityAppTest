using System.Security.Claims;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SafeVaultApp.Models;
using SafeVaultApp.Server.Services;

namespace SafeVaultApp.Server.Endpoints;

internal static class AdminUserEndpoints
{
    public static IEndpointRouteBuilder MapAdminUserEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/admin/users")
            .WithTags("Administrator User Management")
            .RequireAuthorization(policy => policy.RequireRole("Admin"));

        group.MapGet("/", async Task<Ok<IReadOnlyList<ManagedUserResponse>>> (
            IUserManagementService service,
            CancellationToken cancellationToken) =>
                TypedResults.Ok(await service.GetAllAsync(cancellationToken)))
            .WithName("GetManagedUsers")
            .WithSummary("List managed user accounts")
            .WithDescription("Returns registered accounts and their assigned roles. Requires the Admin role.")
            .Produces<IReadOnlyList<ManagedUserResponse>>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden);

        group.MapGet("/{id}", async Task<Results<Ok<ManagedUserResponse>, NotFound>> (
            string id,
            IUserManagementService service,
            CancellationToken cancellationToken) =>
        {
            var user = await service.GetByIdAsync(id, cancellationToken);
            return user is null ? TypedResults.NotFound() : TypedResults.Ok(user);
        })
            .WithName("GetManagedUser")
            .WithSummary("Get a managed user")
            .WithDescription("Returns account details and roles for one registered account.")
            .Produces<ManagedUserResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden);

        group.MapPost("/", async Task<Results<Created<ManagedUserResponse>, ValidationProblem, Conflict<ProblemDetails>>> (
            CreateManagedUserRequest request,
            IUserManagementService service,
            CancellationToken cancellationToken) =>
        {
            var result = await service.CreateAsync(request, cancellationToken);
            if (result.IdentityResult.Succeeded)
            {
                var user = result.User!;
                return TypedResults.Created($"/api/admin/users/{user.Id}", user);
            }

            if (result.IdentityResult.Errors.Any(IsDuplicateIdentityError))
            {
                return TypedResults.Conflict(new ProblemDetails
                {
                    Status = StatusCodes.Status409Conflict,
                    Title = "Account already exists",
                    Detail = "An account with that username or email already exists."
                });
            }

            return ToFailureResult(result);
        })
            .WithName("CreateManagedUser")
            .WithSummary("Create a managed user account")
            .WithDescription("Creates a registered account with the selected role. Requires the Admin role.")
            .Produces<ManagedUserResponse>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden);

        group.MapPut("/{id}/role", async Task<Results<Ok<ManagedUserResponse>, NotFound, ValidationProblem, Conflict<ProblemDetails>>> (
            string id,
            UpdateManagedUserRoleRequest request,
            ClaimsPrincipal principal,
            IUserManagementService service,
            CancellationToken cancellationToken) =>
        {
            var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                return TypedResults.Conflict(new ProblemDetails
                {
                    Status = StatusCodes.Status409Conflict,
                    Title = "Unable to update role",
                    Detail = "The signed-in administrator account could not be identified."
                });
            }

            var result = await service.UpdateRoleAsync(id, request.Role, userId, cancellationToken);
            if (result is null)
            {
                return TypedResults.NotFound();
            }

            if (result.IdentityResult.Succeeded)
            {
                return TypedResults.Ok(result.User!);
            }

            if (result.IsConflict)
            {
                return TypedResults.Conflict(new ProblemDetails
                {
                    Status = StatusCodes.Status409Conflict,
                    Title = "Role change not allowed",
                    Detail = result.IdentityResult.Errors.First().Description
                });
            }

            return ToFailureResult(result);
        })
            .WithName("UpdateManagedUserRole")
            .WithSummary("Change a managed user's role")
            .WithDescription("Assigns User or Admin to a registered account. The last administrator cannot demote themself.")
            .Produces<ManagedUserResponse>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden);

        return endpoints;
    }

    private static ValidationProblem ToFailureResult(ManagedUserOperationResult result)
    {
        var errors = result.IdentityResult.Errors
            .GroupBy(error => string.IsNullOrWhiteSpace(error.Code) ? "account" : error.Code)
            .ToDictionary(group => group.Key, group => group.Select(error => error.Description).ToArray());
        return TypedResults.ValidationProblem(errors);
    }

    private static bool IsDuplicateIdentityError(IdentityError error) =>
        error.Code is nameof(IdentityErrorDescriber.DuplicateUserName) or nameof(IdentityErrorDescriber.DuplicateEmail);
}
