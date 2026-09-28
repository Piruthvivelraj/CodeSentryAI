using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Supabase.Gotrue;
using Blazored.LocalStorage;

namespace CodeSentryAI.Auth;

public class SupabaseAuthStateProvider : AuthenticationStateProvider, IDisposable
{
    private readonly Supabase.Client _supabase;
    private readonly ILocalStorageService _localStorage;
    private bool _isInitialized = false;

    public SupabaseAuthStateProvider(Supabase.Client supabase, ILocalStorageService localStorage)
    {
        _supabase = supabase;
        _localStorage = localStorage;
        _supabase.Auth.AddStateChangedListener(OnAuthStateChanged);
    }

    private void OnAuthStateChanged(Supabase.Gotrue.Interfaces.IGotrueClient<User, Session> client, Constants.AuthState authState)
    {
        _ = HandleAuthStateChange(authState, client.CurrentSession);
    }

    private async Task HandleAuthStateChange(Constants.AuthState authState, Session? session)
    {
        try
        {
            if (authState == Constants.AuthState.SignedIn && session != null)
            {
                await _localStorage.SetItemAsync("supabase_session", session);
            }
            else if (authState == Constants.AuthState.SignedOut)
            {
                await _localStorage.RemoveItemAsync("supabase_session");
            }
        }
        catch { /* Silent fail for storage */ }

        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        if (!_isInitialized)
        {
            try
            {
                var savedSession = await _localStorage.GetItemAsync<Session>("supabase_session");
                if (savedSession != null && !string.IsNullOrEmpty(savedSession.AccessToken))
                {
                    // If the session is expired, the Supabase client might handle refreshing 
                    // if AutoRefreshToken is true, but we need to set the session first.
                    await _supabase.Auth.SetSession(savedSession.AccessToken, savedSession.RefreshToken ?? string.Empty);
                }
            }
            catch { /* Storage might not be available yet */ }
            _isInitialized = true;
        }

        var session = _supabase.Auth.CurrentSession;
        var identity = session?.User != null
            ? new ClaimsIdentity(new[] { 
                new Claim(ClaimTypes.Name, session.User.Email ?? "User"),
                new Claim(ClaimTypes.Email, session.User.Email ?? ""),
                new Claim("id", session.User.Id ?? "")
              }, "supabase")
            : new ClaimsIdentity();

        return new AuthenticationState(new ClaimsPrincipal(identity));
    }

    public void Dispose()
    {
        _supabase.Auth.RemoveStateChangedListener(OnAuthStateChanged);
    }
}
