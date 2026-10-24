using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.AspNetCore.Components.Authorization;
using SafeVaultApp.Services;
using SafeVaultApp;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

var clientAddress = new Uri(builder.HostEnvironment.BaseAddress);
var apiPort = clientAddress.Port switch
{
    5260 => 5259,
    7150 => 7149,
    _ => clientAddress.Port
};
var apiAddress = apiPort == clientAddress.Port
    ? clientAddress
    : new UriBuilder(clientAddress) { Port = apiPort }.Uri;

builder.Services.AddScoped(_ => new HttpClient { BaseAddress = apiAddress });
builder.Services.AddAuthorizationCore();
builder.Services.AddScoped<CookieAuthenticationStateProvider>();
builder.Services.AddScoped<AuthenticationStateProvider>(sp =>
    sp.GetRequiredService<CookieAuthenticationStateProvider>());

await builder.Build().RunAsync();
