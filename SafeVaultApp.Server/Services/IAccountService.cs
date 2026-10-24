using Microsoft.AspNetCore.Identity;
using SafeVaultApp.Models;

namespace SafeVaultApp.Server.Services;

internal sealed record AccountRegistrationResult(AccountResponse? Account, IdentityResult IdentityResult);

internal interface IAccountService
{
    Task<AccountRegistrationResult> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken);
    Task<AccountResponse?> LoginAsync(LoginRequest request, CancellationToken cancellationToken);
    Task SignOutAsync(CancellationToken cancellationToken);
}
