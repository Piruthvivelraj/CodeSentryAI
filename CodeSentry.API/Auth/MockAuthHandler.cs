using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CodeSentry.API.Auth;

/// <summary>
/// Development-only authentication handler that auto-authenticates all requests
/// as a mock user. This allows [Authorize] endpoints to work without a real
/// Supabase JWT secret configured.
/// </summary>
public class MockAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public MockAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, "dev-local-user"),
            new Claim(ClaimTypes.Name, "Local Developer"),
            new Claim(ClaimTypes.Email, "dev@localhost"),
            new Claim("sub", "dev-local-user")
        };

        var identity = new ClaimsIdentity(claims, "Mock");
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, "Mock");

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
