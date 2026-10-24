using System.ComponentModel.DataAnnotations;

namespace SafeVaultApp.Models;

/// <summary>Credentials for an existing SafeVault account.</summary>
public sealed record LoginRequest
{
    [Required, StringLength(64)]
    public required string Username { get; init; }

    [Required, StringLength(128)]
    public required string Password { get; init; }
}

/// <summary>Details required to create a SafeVault account.</summary>
public sealed record RegisterRequest
{
    [Required, StringLength(64, MinimumLength = 3)]
    [RegularExpression(@"^[a-zA-Z0-9_.-]+$")]
    public required string Username { get; init; }

    [Required, EmailAddress, StringLength(256)]
    public required string Email { get; init; }

    [Required, StringLength(128, MinimumLength = 12)]
    public required string Password { get; init; }
}

/// <summary>Safe account details returned after authentication.</summary>
public sealed record AccountResponse(string Username, IReadOnlyList<string> Roles);
