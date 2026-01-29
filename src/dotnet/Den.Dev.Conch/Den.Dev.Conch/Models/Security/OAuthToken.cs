// <copyright file="OAuthToken.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

using System.Text.Json.Serialization;

namespace Den.Dev.Conch.Models.Security
{
    /// <summary>
    /// Container class for the OAuth token.
    /// </summary>
    public class OAuthToken
    {
        /// <summary>
        /// Gets or sets the token type.
        /// </summary>
        [JsonPropertyName("token_type")]
        public string? TokenType { get; set; }

        /// <summary>
        /// Gets or sets the token validity duration.
        /// </summary>
        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }

        /// <summary>
        /// Gets or sets the scope for the token.
        /// </summary>
        [JsonPropertyName("scope")]
        public string? Scope { get; set; }

        /// <summary>
        /// Gets or sets the associated access token.
        /// </summary>
        [JsonPropertyName("access_token")]
        public string? AccessToken { get; set; }

        /// <summary>
        /// Gets or sets the associated refresh token.
        /// </summary>
        [JsonPropertyName("refresh_token")]
        public string? RefreshToken { get; set; }

        /// <summary>
        /// Gets or sets the unique user ID.
        /// </summary>
        [JsonPropertyName("user_id")]
        public string? UserId { get; set; }
    }
}
