using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace SafeVaultApp.Server.Data;

public sealed class VaultDbContext(DbContextOptions<VaultDbContext> options)
    : IdentityDbContext<IdentityUser>(options);
