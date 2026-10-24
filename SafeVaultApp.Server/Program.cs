using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SafeVaultApp.Server.Data;
using SafeVaultApp.Server.Endpoints;
using SafeVaultApp.Server.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<VaultDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("SafeVault")
        ?? "Data Source=App_Data/safevault.db"));
builder.Services.AddIdentityApiEndpoints<IdentityUser>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.Password.RequiredLength = 12;
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
        options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-";
    })
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<VaultDbContext>();
builder.Services.Configure<SecurityStampValidatorOptions>(options =>
    options.ValidationInterval = TimeSpan.Zero);
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name = "SafeVault.Auth";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.Events.OnRedirectToLogin = context =>
    {
        if (context.Request.Path.StartsWithSegments("/api"))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        }

        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
    };
    options.Events.OnRedirectToAccessDenied = context =>
    {
        if (context.Request.Path.StartsWithSegments("/api"))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        }

        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
    };
});
builder.Services.AddAuthorization();
builder.Services.AddValidation();
builder.Services.AddProblemDetails();
builder.Services.AddOpenApi();
builder.Services.AddScoped<IAccountService, AccountService>();
builder.Services.AddScoped<IUserManagementService, UserManagementService>();
builder.Services.AddCors(options =>
{
    options.AddPolicy("BlazorClient", policy =>
        policy.WithOrigins("http://localhost:5260", "https://localhost:7150")
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials());
});

var app = builder.Build();

var connectionString = builder.Configuration.GetConnectionString("SafeVault")
    ?? "Data Source=App_Data/safevault.db";
var databasePath = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(connectionString).DataSource;
if (!string.IsNullOrWhiteSpace(databasePath) && databasePath != ":memory:" && !Path.IsPathRooted(databasePath))
{
    Directory.CreateDirectory(Path.Combine(app.Environment.ContentRootPath, Path.GetDirectoryName(databasePath) ?? "."));
}

await using (var scope = app.Services.CreateAsyncScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<VaultDbContext>();
    await dbContext.Database.EnsureCreatedAsync();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    foreach (var roleName in new[] { "User", "Admin" })
    {
        if (!await roleManager.RoleExistsAsync(roleName))
        {
            var result = await roleManager.CreateAsync(new IdentityRole(roleName));
            if (!result.Succeeded)
            {
                throw new InvalidOperationException($"Could not initialize the {roleName} role.");
            }
        }
    }

    var adminUsername = builder.Configuration["SafeVault:AdminUsername"];
    var adminPassword = builder.Configuration["SafeVault:AdminPassword"];
    if (!string.IsNullOrWhiteSpace(adminUsername) || !string.IsNullOrWhiteSpace(adminPassword))
    {
        if (string.IsNullOrWhiteSpace(adminUsername) || string.IsNullOrWhiteSpace(adminPassword))
        {
            throw new InvalidOperationException("Both SafeVault admin bootstrap settings must be configured together.");
        }

        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var adminUser = await userManager.FindByNameAsync(adminUsername);
        if (adminUser is null)
        {
            adminUser = new IdentityUser
            {
                UserName = adminUsername,
                Email = $"{adminUsername}@example.test"
            };
            var createResult = await userManager.CreateAsync(adminUser, adminPassword);
            if (!createResult.Succeeded)
            {
                var errorCodes = string.Join(", ", createResult.Errors.Select(error => error.Code));
                throw new InvalidOperationException(
                    $"Could not create the configured administrator account: {errorCodes}");
            }
        }

        if (!await userManager.IsInRoleAsync(adminUser, "Admin"))
        {
            var roleResult = await userManager.AddToRoleAsync(adminUser, "Admin");
            if (!roleResult.Succeeded)
            {
                throw new InvalidOperationException("Could not assign the Admin role to the configured account.");
            }
        }
    }
}

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseExceptionHandler();
app.UseStatusCodePages();
app.UseBlazorFrameworkFiles();
app.UseStaticFiles();
app.UseCors("BlazorClient");
app.UseAuthentication();
app.UseAuthorization();
app.MapAuthEndpoints();
app.MapAdminUserEndpoints();
app.MapGet("/api/admin", (CancellationToken cancellationToken) =>
    {
        cancellationToken.ThrowIfCancellationRequested();
        return TypedResults.Ok();
    })
    .WithName("GetAdminDashboard")
    .WithSummary("Check administrator access")
    .WithDescription("Returns success only for authenticated users assigned to the Admin role.")
    .RequireAuthorization(policy => policy.RequireRole("Admin"));
app.MapFallbackToFile("index.html");

await app.RunAsync();

public partial class Program;
