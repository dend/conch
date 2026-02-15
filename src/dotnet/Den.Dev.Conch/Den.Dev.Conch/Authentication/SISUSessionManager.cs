// <copyright file="SISUSessionManager.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Den.Dev.Conch.Models.Security;

namespace Den.Dev.Conch.Authentication
{
    /// <summary>
    /// Manages the Xbox SISU authentication flow, orchestrating device tokens,
    /// OAuth exchanges, and XSTS token acquisition.
    /// </summary>
    public class SISUSessionManager
    {
        private readonly IXboxTokenStore tokenStore;
        private readonly SISUAppConfiguration appConfig;
        private readonly HttpClient? httpClient;

        /// <summary>
        /// Initializes a new instance of the <see cref="SISUSessionManager"/> class.
        /// </summary>
        /// <param name="tokenStore">The token store to use for persistence.</param>
        /// <param name="appConfig">The application configuration for the SISU flow.</param>
        /// <param name="httpClient">Optional HttpClient to pass to the authentication client (e.g. for logging).</param>
        public SISUSessionManager(IXboxTokenStore tokenStore, SISUAppConfiguration appConfig, HttpClient? httpClient = null)
        {
            this.tokenStore = tokenStore;
            this.appConfig = appConfig;
            this.httpClient = httpClient;
        }

        /// <summary>
        /// Attempts to restore a previous session by refreshing the stored OAuth token
        /// and obtaining new XSTS tokens.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The refreshed token cache, or null if restore failed.</returns>
        public async Task<XboxTokenCache?> TryRestoreSessionAsync(CancellationToken cancellationToken = default)
        {
            var cache = this.tokenStore.Load();
            if (cache == null || string.IsNullOrEmpty(cache.RefreshToken))
            {
                return null;
            }

            try
            {
                var authClient = new XboxAuthenticationClient(this.httpClient);

                // Refresh the OAuth token.
                var oauthToken = await authClient.RefreshOAuthToken(
                    this.appConfig.AppId,
                    cache.RefreshToken,
                    this.appConfig.RedirectUri,
                    scopes: this.appConfig.Scopes,
                    cancellationToken: cancellationToken);

                if (oauthToken == null || string.IsNullOrEmpty(oauthToken.AccessToken))
                {
                    return null;
                }

                // Request a new device token (PoP keys are per-instance, can't be cached).
                var deviceToken = await authClient.RequestDeviceToken(cancellationToken: cancellationToken);
                if (deviceToken == null || string.IsNullOrEmpty(deviceToken.Token))
                {
                    return null;
                }

                // Request SISU tokens with the refreshed access token.
                var sisuTokens = await authClient.RequestSISUTokens(
                    deviceToken.Token,
                    oauthToken.AccessToken,
                    this.appConfig.AppId,
                    sandbox: this.appConfig.Sandbox,
                    cancellationToken: cancellationToken);

                if (sisuTokens == null || sisuTokens.AuthorizationToken == null || string.IsNullOrEmpty(sisuTokens.AuthorizationToken.Token))
                {
                    return null;
                }

                var xui = sisuTokens.AuthorizationToken.DisplayClaims?.Xui?.FirstOrDefault();

                cache.AccessToken = oauthToken.AccessToken;
                cache.RefreshToken = oauthToken.RefreshToken;
                cache.XstsToken = sisuTokens.AuthorizationToken.Token;
                cache.UserHash = xui?.UserHash;
                cache.XUID = xui?.XUID;
                cache.Gamertag = xui?.ModernGamertag ?? xui?.Gamertag;
                cache.OAuthExpiresAt = DateTimeOffset.UtcNow.AddSeconds(oauthToken.ExpiresIn);
                cache.XstsExpiresAt = sisuTokens.AuthorizationToken.NotAfter;

                this.tokenStore.Save(cache);
                return cache;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>
        /// Initiates the SISU login flow by requesting a device token and SISU session.
        /// The returned <see cref="SISUSessionInfo"/> must be passed to <see cref="CompleteSISULoginAsync"/>
        /// along with the authorization code obtained by the user.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Session info containing the OAuth URL and session state, or null on failure.</returns>
        public async Task<SISUSessionInfo?> InitiateSISULoginAsync(CancellationToken cancellationToken = default)
        {
            var authClient = new XboxAuthenticationClient(this.httpClient);

            var deviceToken = await authClient.RequestDeviceToken(cancellationToken: cancellationToken);
            if (deviceToken == null || string.IsNullOrEmpty(deviceToken.Token))
            {
                return null;
            }

            var sisuSession = await authClient.RequestSISUSession(
                this.appConfig.AppId,
                this.appConfig.TitleId,
                deviceToken.Token,
                new List<string>(this.appConfig.Scopes),
                this.appConfig.RedirectUri,
                this.appConfig.TokenType,
                this.appConfig.Sandbox,
                cancellationToken);

            if (sisuSession == null || string.IsNullOrEmpty(sisuSession.MSAOAuthRedirect))
            {
                return null;
            }

            return new SISUSessionInfo
            {
                OAuthUrl = sisuSession.MSAOAuthRedirect,
                SessionId = sisuSession.SessionId,
                DeviceToken = deviceToken.Token,
                AuthClient = authClient,
            };
        }

        /// <summary>
        /// Completes the SISU login flow using the authorization code provided by the user.
        /// </summary>
        /// <param name="sessionInfo">Session info from <see cref="InitiateSISULoginAsync"/>.</param>
        /// <param name="code">The authorization code from the OAuth redirect.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The populated token cache, or null on failure.</returns>
        public async Task<XboxTokenCache?> CompleteSISULoginAsync(SISUSessionInfo sessionInfo, string code, CancellationToken cancellationToken = default)
        {
            if (sessionInfo.AuthClient == null)
            {
                return null;
            }

            // Use the same auth client instance to ensure the code verifier matches.
            var oauthToken = await sessionInfo.AuthClient.RequestOAuthToken(
                this.appConfig.AppId,
                code,
                this.appConfig.RedirectUri,
                scopes: this.appConfig.Scopes,
                useCodeVerifier: true,
                cancellationToken: cancellationToken);

            if (oauthToken == null || string.IsNullOrEmpty(oauthToken.AccessToken))
            {
                return null;
            }

            var sisuTokens = await sessionInfo.AuthClient.RequestSISUTokens(
                sessionInfo.DeviceToken!,
                oauthToken.AccessToken,
                this.appConfig.AppId,
                sessionInfo.SessionId,
                this.appConfig.Sandbox,
                cancellationToken: cancellationToken);

            if (sisuTokens == null || sisuTokens.AuthorizationToken == null || string.IsNullOrEmpty(sisuTokens.AuthorizationToken.Token))
            {
                return null;
            }

            var xui = sisuTokens.AuthorizationToken.DisplayClaims?.Xui?.FirstOrDefault();

            var cache = new XboxTokenCache
            {
                AccessToken = oauthToken.AccessToken,
                RefreshToken = oauthToken.RefreshToken,
                XstsToken = sisuTokens.AuthorizationToken.Token,
                UserHash = xui?.UserHash,
                XUID = xui?.XUID,
                Gamertag = xui?.ModernGamertag ?? xui?.Gamertag,
                OAuthExpiresAt = DateTimeOffset.UtcNow.AddSeconds(oauthToken.ExpiresIn),
                XstsExpiresAt = sisuTokens.AuthorizationToken.NotAfter,
            };

            this.tokenStore.Save(cache);
            return cache;
        }

        /// <summary>
        /// Clears all stored authentication tokens.
        /// </summary>
        public void ClearStoredTokens()
        {
            this.tokenStore.Clear();
        }
    }
}
