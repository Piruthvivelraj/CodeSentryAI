using System.Net.Http.Headers;
using Blazored.LocalStorage;
using Supabase.Gotrue;

namespace CodeSentryAI.Auth;

/// <summary>
/// Attaches the Supabase JWT access token to outgoing API requests.
/// 
/// IMPORTANT: IHttpClientFactory creates DelegatingHandlers in a SEPARATE DI scope,
/// so we cannot rely on the injected Supabase.Client having the same session as
/// the rest of the app. Instead, we read the session directly from localStorage
/// (the source of truth persisted by SupabaseAuthStateProvider) AND also check
/// the Supabase client as a fallback.
/// </summary>
public class SupabaseAuthorizationHandler : DelegatingHandler
{
    private readonly Supabase.Client _supabase;
    private readonly ISyncLocalStorageService _localStorage;

    public SupabaseAuthorizationHandler(Supabase.Client supabase, ISyncLocalStorageService localStorage)
    {
        _supabase = supabase;
        _localStorage = localStorage;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        string? token = null;

        // 1. Try the Supabase client's current session first (fastest path)
        var session = _supabase.Auth.CurrentSession;
        if (session != null && !string.IsNullOrEmpty(session.AccessToken))
        {
            token = session.AccessToken;
        }

        // 2. Fallback: read persisted session from localStorage
        //    This handles the case where IHttpClientFactory creates a fresh DI scope
        //    with a new Supabase.Client that doesn't have the session yet.
        if (string.IsNullOrEmpty(token))
        {
            try
            {
                var savedSession = _localStorage.GetItem<Session>("supabase_session");
                if (savedSession != null && !string.IsNullOrEmpty(savedSession.AccessToken))
                {
                    token = savedSession.AccessToken;

                    // Also restore the session into the Supabase client for future calls
                    try
                    {
                        await _supabase.Auth.SetSession(savedSession.AccessToken, savedSession.RefreshToken ?? string.Empty);
                    }
                    catch { /* Best effort */ }
                }
            }
            catch { /* localStorage might not be available */ }
        }

        if (!string.IsNullOrEmpty(token))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        return await base.SendAsync(request, cancellationToken);
    }
}
