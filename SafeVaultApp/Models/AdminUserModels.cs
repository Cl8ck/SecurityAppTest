using System.ComponentModel.DataAnnotations;

namespace SafeVaultApp.Models;

/// <summary>Details for creating an account from the administrator dashboard.</summary>
public sealed record CreateManagedUserRequest
{
    [Required, StringLength(64, MinimumLength = 3)]
    [RegularExpression(@"^[a-zA-Z0-9_.-]+$")]
    public required string Username { get; init; }

    [Required, EmailAddress, StringLength(256)]
    public required string Email { get; init; }

    [Required, StringLength(128, MinimumLength = 12)]
    [RegularExpression(
        @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).+$",
        ErrorMessage = "Password must include uppercase, lowercase, a number, and a symbol.")]
    public required string Password { get; init; }

    [Required, RegularExpression("^(User|Admin)$")]
    public required string Role { get; init; }
}

/// <summary>Role to assign to an existing managed account.</summary>
public sealed record UpdateManagedUserRoleRequest
{
    [Required, RegularExpression("^(User|Admin)$")]
    public required string Role { get; init; }
}

/// <summary>Account details and roles displayed in the administrator dashboard.</summary>
public sealed record ManagedUserResponse(
    string Id,
    string Username,
    string? Email,
    IReadOnlyList<string> Roles);
