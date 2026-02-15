// <copyright file="XboxTokenCache.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

using System;
using System.Text.Json.Serialization;
using Den.Dev.Conch.Authentication;

namespace Den.Dev.Conch.Models.Security
{
    /// <summary>
    /// Represents cached Xbox authentication tokens, suitable for serialization and persistence.
    /// </summary>
    public class XboxTokenCache
    {
        /// <summary>
        /// Gets or sets the OAuth access token.
        /// </summary>
        [JsonPropertyName("access_token")]
        public string? AccessToken { get; set; }

        /// <summary>
        /// Gets or sets the OAuth refresh token.
        /// </summary>
        [JsonPropertyName("refresh_token")]
        public string? RefreshToken { get; set; }

        /// <summary>
        /// Gets or sets the XSTS token.
        /// </summary>
        [JsonPropertyName("xsts_token")]
        public string? XstsToken { get; set; }

        /// <summary>
        /// Gets or sets the user hash.
        /// </summary>
        [JsonPropertyName("user_hash")]
        public string? UserHash { get; set; }

        /// <summary>
        /// Gets or sets the Xbox User ID (XUID).
        /// </summary>
        [JsonPropertyName("xuid")]
        public string? XUID { get; set; }

        /// <summary>
        /// Gets or sets the user's gamertag.
        /// </summary>
        [JsonPropertyName("gamertag")]
        public string? Gamertag { get; set; }

        /// <summary>
        /// Gets or sets the OAuth token expiry timestamp.
        /// </summary>
        [JsonPropertyName("oauth_expires_at")]
        public DateTimeOffset OAuthExpiresAt { get; set; }

        /// <summary>
        /// Gets or sets the XSTS token expiry timestamp.
        /// </summary>
        [JsonPropertyName("xsts_expires_at")]
        public DateTimeOffset XstsExpiresAt { get; set; }

        /// <summary>
        /// Gets the formatted XBL3.0 authorization header value, or null if the required
        /// token fields are missing.
        /// </summary>
        [JsonIgnore]
        public string? AuthorizationHeaderValue
        {
            get
            {
                if (string.IsNullOrEmpty(this.UserHash) || string.IsNullOrEmpty(this.XstsToken))
                {
                    return null;
                }

                return XboxAuthenticationClient.FormatXboxLiveV3Token(this.UserHash, this.XstsToken);
            }
        }
    }
}
