using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SafeVaultApp.Models;

namespace SafeVaultApp.Server.Services;

internal sealed class UserManagementService(
    UserManager<IdentityUser> userManager,
    RoleManager<IdentityRole> roleManager,
    SignInManager<IdentityUser> signInManager) : IUserManagementService
{
    private static readonly string[] ManagedRoles = ["User", "Admin"];

    public async Task<IReadOnlyList<ManagedUserResponse>> GetAllAsync(CancellationToken cancellationToken)
    {
        var users = await userManager.Users
            .AsNoTracking()
            .OrderBy(user => user.UserName)
            .ToListAsync(cancellationToken);
        var results = new List<ManagedUserResponse>(users.Count);

        foreach (var user in users)
        {
            cancellationToken.ThrowIfCancellationRequested();
            results.Add(await ToResponseAsync(user));
        }

        return results;
    }

    public async Task<ManagedUserResponse?> GetByIdAsync(string id, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var user = await userManager.FindByIdAsync(id);
        return user is null ? null : await ToResponseAsync(user);
    }

    public async Task<ManagedUserOperationResult> CreateAsync(
        CreateManagedUserRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!await roleManager.RoleExistsAsync(request.Role))
        {
            return Failed("role", "The selected role does not exist.");
        }

        var user = new IdentityUser
        {
            UserName = request.Username,
            Email = request.Email
        };
        var createResult = await userManager.CreateAsync(user, request.Password);
        if (!createResult.Succeeded)
        {
            return new ManagedUserOperationResult(null, createResult);
        }

        var roleResult = await userManager.AddToRoleAsync(user, request.Role);
        if (!roleResult.Succeeded)
        {
            var rollbackResult = await userManager.DeleteAsync(user);
            if (!rollbackResult.Succeeded)
            {
                throw new InvalidOperationException("Could not roll back a failed managed-user creation.");
            }

            return new ManagedUserOperationResult(null, roleResult);
        }

        return new ManagedUserOperationResult(await ToResponseAsync(user), IdentityResult.Success);
    }

    public async Task<ManagedUserOperationResult?> UpdateRoleAsync(
        string id,
        string role,
        string requestingUserId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            return null;
        }

        if (!await roleManager.RoleExistsAsync(role))
        {
            return Failed("role", "The selected role does not exist.");
        }

        var currentRoles = await userManager.GetRolesAsync(user);
        if (currentRoles.Contains(role, StringComparer.Ordinal))
        {
            return new ManagedUserOperationResult(await ToResponseAsync(user), IdentityResult.Success);
        }

        if (role == "User" && currentRoles.Contains("Admin", StringComparer.Ordinal))
        {
            var administrators = await userManager.GetUsersInRoleAsync("Admin");
            if (administrators.Count <= 1)
            {
                return Failed("role", "The last administrator cannot be changed to the User role.", isConflict: true);
            }
        }

        var addResult = await userManager.AddToRoleAsync(user, role);
        if (!addResult.Succeeded)
        {
            return new ManagedUserOperationResult(null, addResult);
        }

        var rolesToRemove = currentRoles.Where(currentRole =>
            ManagedRoles.Contains(currentRole, StringComparer.Ordinal));
        if (rolesToRemove.Any())
        {
            var removeResult = await userManager.RemoveFromRolesAsync(user, rolesToRemove);
            if (!removeResult.Succeeded)
            {
                var rollbackResult = await userManager.RemoveFromRoleAsync(user, role);
                if (!rollbackResult.Succeeded)
                {
                    throw new InvalidOperationException("Could not roll back a failed managed-user role update.");
                }

                return new ManagedUserOperationResult(null, removeResult);
            }
        }

        var securityStampResult = await userManager.UpdateSecurityStampAsync(user);
        if (!securityStampResult.Succeeded)
        {
            throw new InvalidOperationException("Could not refresh the user's security stamp after a role change.");
        }

        if (string.Equals(user.Id, requestingUserId, StringComparison.Ordinal))
        {
            await signInManager.RefreshSignInAsync(user);
        }

        return new ManagedUserOperationResult(await ToResponseAsync(user), IdentityResult.Success);
    }

    private async Task<ManagedUserResponse> ToResponseAsync(IdentityUser user)
    {
        var roles = await userManager.GetRolesAsync(user);
        return new ManagedUserResponse(user.Id, user.UserName ?? string.Empty, user.Email, roles.ToArray());
    }

    private static ManagedUserOperationResult Failed(string code, string description, bool isConflict = false) =>
        new(null, IdentityResult.Failed(new IdentityError { Code = code, Description = description }), isConflict);
}
