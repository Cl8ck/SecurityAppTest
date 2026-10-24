using System.Security.Claims;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.WebAssembly.Http;

namespace SafeVaultApp.Services;

public sealed class CookieAuthenticationStateProvider(
    HttpClient httpClient,
    ILogger<CookieAuthenticationStateProvider> logger) : AuthenticationStateProvider
{
    private static readonly AuthenticationState Anonymous = new(new ClaimsPrincipal(new ClaimsIdentity()));

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "api/auth/me");
        request.SetBrowserRequestCredentials(BrowserRequestCredentials.Include);
        using var response = await httpClient.SendAsync(request);
        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            return Anonymous;
        }

        if (!response.IsSuccessStatusCode ||
            response.Content.Headers.ContentType?.MediaType != "application/json")
        {
            logger.LogError(
                "The current-account endpoint returned unexpected status/content type: {StatusCode}, {ContentType}.",
                response.StatusCode,
                response.Content.Headers.ContentType?.MediaType ?? "(missing)");
            return Anonymous;
        }

        Models.AccountResponse? account;
        try
        {
            account = await response.Content.ReadFromJsonAsync<Models.AccountResponse>();
        }
        catch (JsonException exception)
        {
            logger.LogError(exception, "The current-account endpoint returned invalid JSON.");
            return Anonymous;
        }

        if (account is null)
        {
            logger.LogError("The current-account endpoint returned an empty response.");
            return Anonymous;
        }

        return CreateAuthenticationState(account);
    }

    public async Task RefreshAsync()
    {
        var state = await GetAuthenticationStateAsync();
        NotifyAuthenticationStateChanged(Task.FromResult(state));
    }

    public async Task SignOutAsync()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/auth/logout");
        request.SetBrowserRequestCredentials(BrowserRequestCredentials.Include);
        using var response = await httpClient.SendAsync(request);
        response.EnsureSuccessStatusCode();
        NotifyAuthenticationStateChanged(Task.FromResult(Anonymous));
    }

    private static AuthenticationState CreateAuthenticationState(Models.AccountResponse account)
    {
        var claims = new List<Claim> { new(ClaimTypes.Name, account.Username) };
        claims.AddRange(account.Roles.Select(role => new Claim(ClaimTypes.Role, role)));
        return new AuthenticationState(new ClaimsPrincipal(
            new ClaimsIdentity(claims, authenticationType: "SafeVaultCookie")));
    }
}
