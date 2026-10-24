using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using SafeVaultApp.Models;

namespace SafeVaultApp.Tests;

public sealed class AuthenticationTests
{
    [Fact]
    public async Task RegistrationSignsInAndRestrictsAdminAccessForRegularUsers()
    {
        using var factory = new SafeVaultApiFactory();
        using var client = factory.CreateClient();

        var registration = await client.PostAsJsonAsync("api/auth/register", ValidRegistration);

        Assert.Equal(HttpStatusCode.Created, registration.StatusCode);
        using var account = JsonDocument.Parse(await registration.Content.ReadAsStringAsync());
        Assert.Equal("vaultuser", account.RootElement.GetProperty("username").GetString());
        Assert.Contains("User", account.RootElement.GetProperty("roles").EnumerateArray().Select(role => role.GetString()));

        Assert.Equal(
            HttpStatusCode.Conflict,
            (await client.PostAsJsonAsync("api/auth/register", ValidRegistration)).StatusCode);

        var currentAccount = await client.GetAsync("api/auth/me");
        Assert.Equal(HttpStatusCode.OK, currentAccount.StatusCode);
        var openApiResponse = await client.GetAsync("openapi/v1.json");
        Assert.Equal(HttpStatusCode.OK, openApiResponse.StatusCode);
        Assert.Contains("/api/auth/login", await openApiResponse.Content.ReadAsStringAsync());

        var adminDashboard = await client.GetAsync("api/admin");
        Assert.Equal(HttpStatusCode.Forbidden, adminDashboard.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("api/auth/logout", content: null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task InvalidCredentialsAndAnonymousProtectedRequestsAreRejected()
    {
        using var factory = new SafeVaultApiFactory();
        using var client = factory.CreateClient();

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("api/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("api/admin")).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await client.PostAsJsonAsync("api/auth/register", ValidRegistration)).StatusCode);

        var login = await client.PostAsJsonAsync("api/auth/login", new LoginRequest
        {
            Username = "vaultuser",
            Password = "Wrong!Password123"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
    }

    [Fact]
    public async Task RegistrationReturnsPasswordPolicyValidationErrors()
    {
        using var factory = new SafeVaultApiFactory();
        using var client = factory.CreateClient();
        var request = new RegisterRequest
        {
            Username = "vaultuser",
            Email = "vaultuser@example.test",
            Password = "LongPasswordWithoutSymbols123"
        };

        using var response = await client.PostAsJsonAsync("api/auth/register", request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.NotNull(problem);
        Assert.Contains(
            "PasswordRequiresNonAlphanumeric",
            problem.RootElement.GetProperty("errors").EnumerateObject().Select(error => error.Name));
    }

    [Fact]
    public async Task AdminRoleCanAccessRestrictedDashboard()
    {
        using var factory = new SafeVaultApiFactory("vaultadmin", "Practice!AdminPassword123");
        using var client = factory.CreateClient();

        var login = await client.PostAsJsonAsync("api/auth/login", new LoginRequest
        {
            Username = "vaultadmin",
            Password = "Practice!AdminPassword123"
        });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("api/admin")).StatusCode);
    }

    [Fact]
    public async Task AdminCanListCreateAndChangeManagedUserRoles()
    {
        using var factory = new SafeVaultApiFactory("vaultadmin", "Practice!AdminPassword123");
        using var client = factory.CreateClient();
        await SignInAsAdminAsync(client);

        var usersResponse = await client.GetAsync("api/admin/users");
        Assert.Equal(HttpStatusCode.OK, usersResponse.StatusCode);
        var initialUsers = await usersResponse.Content.ReadFromJsonAsync<List<ManagedUserResponse>>();
        Assert.NotNull(initialUsers);
        var administrator = Assert.Single(initialUsers, user => user.Username == "vaultadmin");
        Assert.Contains("Admin", administrator.Roles);

        using var createResponse = await client.PostAsJsonAsync("api/admin/users", new CreateManagedUserRequest
        {
            Username = "manageduser",
            Email = "manageduser@example.test",
            Password = "Practice!ManagedUser123",
            Role = "User"
        });
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
        var createdUser = await createResponse.Content.ReadFromJsonAsync<ManagedUserResponse>();
        Assert.NotNull(createdUser);
        Assert.Contains("User", createdUser.Roles);
        Assert.NotNull(createResponse.Headers.Location);
        Assert.Equal($"/api/admin/users/{createdUser.Id}", createResponse.Headers.Location!.OriginalString);
        var createdUserResponse = await client.GetAsync(createResponse.Headers.Location);
        Assert.Equal(HttpStatusCode.OK, createdUserResponse.StatusCode);

        var list = await client.GetFromJsonAsync<List<ManagedUserResponse>>("api/admin/users");
        Assert.NotNull(list);
        Assert.Contains(list, user => user.Username == "manageduser" && user.Roles.Contains("User"));

        var roleResponse = await client.PutAsJsonAsync(
            $"api/admin/users/{createdUser.Id}/role",
            new UpdateManagedUserRoleRequest { Role = "Admin" });
        Assert.Equal(HttpStatusCode.OK, roleResponse.StatusCode);
        var updatedUser = await roleResponse.Content.ReadFromJsonAsync<ManagedUserResponse>();
        Assert.NotNull(updatedUser);
        Assert.Contains("Admin", updatedUser.Roles);
        Assert.DoesNotContain("User", updatedUser.Roles);

        var ownRoleResponse = await client.PutAsJsonAsync(
            $"api/admin/users/{administrator.Id}/role",
            new UpdateManagedUserRoleRequest { Role = "User" });
        Assert.Equal(HttpStatusCode.OK, ownRoleResponse.StatusCode);
        var currentAccount = await client.GetFromJsonAsync<AccountResponse>("api/auth/me");
        Assert.NotNull(currentAccount);
        Assert.Contains("User", currentAccount.Roles);
        Assert.DoesNotContain("Admin", currentAccount.Roles);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("api/admin/users")).StatusCode);
    }

    [Fact]
    public async Task LastAdministratorCannotDemoteThemself()
    {
        using var factory = new SafeVaultApiFactory("vaultadmin", "Practice!AdminPassword123");
        using var client = factory.CreateClient();
        await SignInAsAdminAsync(client);
        var users = await client.GetFromJsonAsync<List<ManagedUserResponse>>("api/admin/users");
        Assert.NotNull(users);
        var administrator = Assert.Single(users, user => user.Username == "vaultadmin");

        var response = await client.PutAsJsonAsync(
            $"api/admin/users/{administrator.Id}/role",
            new UpdateManagedUserRoleRequest { Role = "User" });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        var error = await response.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.NotNull(error);
        Assert.Contains(
            "last administrator",
            error.RootElement.GetProperty("detail").GetString(),
            StringComparison.OrdinalIgnoreCase);

        var usersAfterAttempt = await client.GetFromJsonAsync<List<ManagedUserResponse>>("api/admin/users");
        Assert.NotNull(usersAfterAttempt);
        var remainingAdministrator = Assert.Single(usersAfterAttempt, user => user.Username == "vaultadmin");
        Assert.Contains("Admin", remainingAdministrator.Roles);
    }

    [Fact]
    public async Task DemotedAdministratorLosesAccessOnTheirNextRequest()
    {
        using var factory = new SafeVaultApiFactory("vaultadmin", "Practice!AdminPassword123");
        using var administratorClient = factory.CreateClient();
        await SignInAsAdminAsync(administratorClient);

        using var createResponse = await administratorClient.PostAsJsonAsync("api/admin/users", new CreateManagedUserRequest
        {
            Username = "secondadmin",
            Email = "secondadmin@example.test",
            Password = "Practice!SecondAdmin123",
            Role = "Admin"
        });
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
        var secondAdmin = await createResponse.Content.ReadFromJsonAsync<ManagedUserResponse>();
        Assert.NotNull(secondAdmin);

        using var secondAdminClient = factory.CreateClient();
        var secondAdminLogin = await secondAdminClient.PostAsJsonAsync("api/auth/login", new LoginRequest
        {
            Username = "secondadmin",
            Password = "Practice!SecondAdmin123"
        });
        Assert.Equal(HttpStatusCode.OK, secondAdminLogin.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await secondAdminClient.GetAsync("api/admin/users")).StatusCode);

        var demotion = await administratorClient.PutAsJsonAsync(
            $"api/admin/users/{secondAdmin.Id}/role",
            new UpdateManagedUserRoleRequest { Role = "User" });
        Assert.Equal(HttpStatusCode.OK, demotion.StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await secondAdminClient.GetAsync("api/admin/users")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await secondAdminClient.GetAsync("api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task RegularUsersCannotManageAccounts()
    {
        using var factory = new SafeVaultApiFactory();
        using var client = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Created, (await client.PostAsJsonAsync("api/auth/register", ValidRegistration)).StatusCode);

        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("api/admin/users")).StatusCode);
    }

    [Fact]
    public async Task StandaloneClientCanMakeCredentialedCrossOriginRequests()
    {
        using var factory = new SafeVaultApiFactory();
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Options, "api/auth/login");
        request.Headers.Add("Origin", "http://localhost:5260");
        request.Headers.Add("Access-Control-Request-Method", "POST");
        request.Headers.Add("Access-Control-Request-Headers", "content-type");

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal("http://localhost:5260", response.Headers.GetValues("Access-Control-Allow-Origin").Single());
        Assert.Contains("true", response.Headers.GetValues("Access-Control-Allow-Credentials"));
    }

    [Theory]
    [InlineData("<script>alert(1)</script>")]
    [InlineData("' OR 1=1--")]
    public async Task RegistrationRejectsInjectionAndMarkupInUsername(string username)
    {
        using var factory = new SafeVaultApiFactory();
        using var client = factory.CreateClient();

        var registration = await client.PostAsJsonAsync("api/auth/register", new RegisterRequest
        {
            Username = username,
            Email = "invalid@example.test",
            Password = "Practice!Password123"
        });

        Assert.Equal(HttpStatusCode.BadRequest, registration.StatusCode);
    }

    private static RegisterRequest ValidRegistration => new()
    {
        Username = "vaultuser",
        Email = "vaultuser@example.test",
        Password = "Practice!Password123"
    };

    private static async Task SignInAsAdminAsync(HttpClient client)
    {
        var login = await client.PostAsJsonAsync("api/auth/login", new LoginRequest
        {
            Username = "vaultadmin",
            Password = "Practice!AdminPassword123"
        });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
    }

    private sealed class SafeVaultApiFactory : WebApplicationFactory<Program>
    {
        private readonly string databaseDirectory = Path.Combine(
            Path.GetTempPath(),
            "SafeVaultApp.Tests",
            Guid.NewGuid().ToString("N"));
        private readonly string? adminUsername;
        private readonly string? adminPassword;

        public SafeVaultApiFactory(string? adminUsername = null, string? adminPassword = null)
        {
            Directory.CreateDirectory(databaseDirectory);
            this.adminUsername = adminUsername;
            this.adminPassword = adminPassword;
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                var settings = new Dictionary<string, string?>
                {
                    ["ConnectionStrings:SafeVault"] = $"Data Source={Path.Combine(databaseDirectory, "test.db")};Pooling=False",
                    ["Logging:LogLevel:Default"] = "Warning",
                    ["Logging:LogLevel:Microsoft.AspNetCore"] = "Warning"
                };
                if (adminUsername is not null && adminPassword is not null)
                {
                    settings["SafeVault:AdminUsername"] = adminUsername;
                    settings["SafeVault:AdminPassword"] = adminPassword;
                }

                configuration.AddInMemoryCollection(settings);
            });
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing && Directory.Exists(databaseDirectory))
            {
                Directory.Delete(databaseDirectory, recursive: true);
            }
        }
    }
}
