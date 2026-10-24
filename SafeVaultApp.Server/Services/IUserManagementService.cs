using Microsoft.AspNetCore.Identity;
using SafeVaultApp.Models;

namespace SafeVaultApp.Server.Services;

internal sealed record ManagedUserOperationResult(
    ManagedUserResponse? User,
    IdentityResult IdentityResult,
    bool IsConflict = false);

internal interface IUserManagementService
{
    Task<IReadOnlyList<ManagedUserResponse>> GetAllAsync(CancellationToken cancellationToken);
    Task<ManagedUserResponse?> GetByIdAsync(string id, CancellationToken cancellationToken);
    Task<ManagedUserOperationResult> CreateAsync(
        CreateManagedUserRequest request,
        CancellationToken cancellationToken);
    Task<ManagedUserOperationResult?> UpdateRoleAsync(
        string id,
        string role,
        string requestingUserId,
        CancellationToken cancellationToken);
}
