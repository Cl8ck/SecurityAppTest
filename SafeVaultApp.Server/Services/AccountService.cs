using Microsoft.AspNetCore.Identity;
using SafeVaultApp.Models;

namespace SafeVaultApp.Server.Services;

internal sealed class AccountService(
    UserManager<IdentityUser> userManager,
    SignInManager<IdentityUser> signInManager) : IAccountService
{
    public async Task<AccountRegistrationResult> RegisterAsync(
        RegisterRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var user = new IdentityUser
        {
            UserName = request.Username,
            Email = request.Email
        };
        var createResult = await userManager.CreateAsync(user, request.Password);
        if (!createResult.Succeeded)
        {
            return new AccountRegistrationResult(null, createResult);
        }

        var roleResult = await userManager.AddToRoleAsync(user, "User");
        if (!roleResult.Succeeded)
        {
            var rollbackResult = await userManager.DeleteAsync(user);
            if (!rollbackResult.Succeeded)
            {
                throw new InvalidOperationException("Could not roll back a failed account registration.");
            }

            return new AccountRegistrationResult(null, roleResult);
        }

        await signInManager.SignInAsync(user, isPersistent: false);
        var roles = await userManager.GetRolesAsync(user);
        return new AccountRegistrationResult(
            new AccountResponse(user.UserName!, roles.ToArray()),
            IdentityResult.Success);
    }

    public async Task<AccountResponse?> LoginAsync(LoginRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var user = await userManager.FindByNameAsync(request.Username);
        if (user is null)
        {
            return null;
        }

        var result = await signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
        if (!result.Succeeded)
        {
            return null;
        }

        await signInManager.SignInAsync(user, isPersistent: false);
        var roles = await userManager.GetRolesAsync(user);
        return new AccountResponse(user.UserName!, roles.ToArray());
    }

    public async Task SignOutAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await signInManager.SignOutAsync();
    }
}
