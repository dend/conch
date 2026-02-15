// <copyright file="XboxTokenRefreshHandler.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace Den.Dev.Conch.Authentication
{
    /// <summary>
    /// HTTP delegating handler that intercepts 401 Unauthorized responses,
    /// refreshes the Xbox authentication tokens, and retries the request once.
    /// </summary>
    public class XboxTokenRefreshHandler : DelegatingHandler
    {
        private readonly SISUSessionManager sessionManager;
        private readonly IXboxTokenStore tokenStore;
        private readonly SemaphoreSlim refreshLock = new SemaphoreSlim(1, 1);

        /// <summary>
        /// Initializes a new instance of the <see cref="XboxTokenRefreshHandler"/> class
        /// with a default <see cref="HttpClientHandler"/> as the inner handler.
        /// </summary>
        /// <param name="sessionManager">The session manager used to refresh tokens.</param>
        /// <param name="tokenStore">The token store used to read refreshed tokens.</param>
        public XboxTokenRefreshHandler(SISUSessionManager sessionManager, IXboxTokenStore tokenStore)
            : base(new HttpClientHandler())
        {
            this.sessionManager = sessionManager;
            this.tokenStore = tokenStore;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="XboxTokenRefreshHandler"/> class
        /// with a specified inner handler for chaining.
        /// </summary>
        /// <param name="sessionManager">The session manager used to refresh tokens.</param>
        /// <param name="tokenStore">The token store used to read refreshed tokens.</param>
        /// <param name="innerHandler">The inner handler to delegate to.</param>
        public XboxTokenRefreshHandler(SISUSessionManager sessionManager, IXboxTokenStore tokenStore, HttpMessageHandler innerHandler)
            : base(innerHandler)
        {
            this.sessionManager = sessionManager;
            this.tokenStore = tokenStore;
        }

        /// <inheritdoc/>
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = await base.SendAsync(request, cancellationToken);

            if (response.StatusCode != HttpStatusCode.Unauthorized)
            {
                return response;
            }

            await this.refreshLock.WaitAsync(cancellationToken);
            try
            {
                var refreshedCache = await this.sessionManager.TryRestoreSessionAsync(cancellationToken);
                if (refreshedCache == null)
                {
                    return response;
                }

                var authHeader = refreshedCache.AuthorizationHeaderValue;
                if (string.IsNullOrEmpty(authHeader))
                {
                    return response;
                }

                // Clone the original request for the retry (the original has already been sent).
                var retry = await CloneRequestAsync(request);
                retry.Headers.Authorization = new AuthenticationHeaderValue(
                    "XBL3.0",
                    authHeader.Replace("XBL3.0 ", string.Empty));

                response.Dispose();
                return await base.SendAsync(retry, cancellationToken);
            }
            finally
            {
                this.refreshLock.Release();
            }
        }

        private static async Task<HttpRequestMessage> CloneRequestAsync(HttpRequestMessage request)
        {
            var clone = new HttpRequestMessage(request.Method, request.RequestUri);

            if (request.Content != null)
            {
                var content = await request.Content.ReadAsByteArrayAsync();
                clone.Content = new ByteArrayContent(content);

                foreach (var header in request.Content.Headers)
                {
                    clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }

            foreach (var header in request.Headers)
            {
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            clone.Version = request.Version;

            return clone;
        }
    }
}
