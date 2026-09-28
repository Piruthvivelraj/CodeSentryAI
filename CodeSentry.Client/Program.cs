using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Supabase;
using CodeSentryAI;
using CodeSentryAI.Auth;
using Microsoft.AspNetCore.Components.Authorization;
using Blazored.LocalStorage;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

var apiBase = builder.Configuration["ApiBaseUrl"] ?? "http://localhost:5001/";

builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress), Timeout = TimeSpan.FromSeconds(120) });
builder.Services.AddScoped<SupabaseAuthorizationHandler>();
builder.Services.AddHttpClient("CodeSentryAPI", client => { 
    client.BaseAddress = new Uri(apiBase); 
    client.Timeout = TimeSpan.FromSeconds(120); 
}).AddHttpMessageHandler<SupabaseAuthorizationHandler>();

builder.Services.AddAuthorizationCore();
builder.Services.AddScoped<AuthenticationStateProvider, SupabaseAuthStateProvider>();
builder.Services.AddScoped<CodeSentryAI.Services.MockDataService>();
builder.Services.AddScoped<CodeSentryAI.Services.ToastService>();
builder.Services.AddBlazoredLocalStorage();

var supabaseUrl = builder.Configuration["Supabase:Url"] ?? throw new InvalidOperationException("Supabase URL is missing.");
var supabaseKey = builder.Configuration["Supabase:Key"] ?? throw new InvalidOperationException("Supabase Key is missing.");

builder.Services.AddScoped<Supabase.Client>(_ =>
{
    var options = new SupabaseOptions { AutoRefreshToken = true, AutoConnectRealtime = false };
    return new Supabase.Client(supabaseUrl, supabaseKey, options);
});

await builder.Build().RunAsync();
