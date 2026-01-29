// <copyright file="SISUAuthenticationResponse.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

using System.Text.Json.Serialization;

namespace Den.Dev.Conch.Models.Security
{
    /// <summary>
    /// Container class representing a SISU authentication response, including the OAuth redirect URL and session information.
    /// </summary>
    public class SISUAuthenticationResponse
    {
        /// <summary>
        /// Gets or sets the redirect URL where the user needs to go to receieve authentication code.
        /// </summary>
        [JsonPropertyName("MsaOauthRedirect")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? MSAOAuthRedirect { get; set; }

        /// <summary>
        /// Gets or sets additional MSA request parameters.
        /// </summary>
        [JsonPropertyName("MsaRequestParameters")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public MSARequestParameters? MSARequestParameters { get; set; }

        /// <summary>
        /// Gets or sets the session ID. Populated automatically within Conch when authenticating against SISU from the X-SessionId header.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
        public string? SessionId { get; set; }
    }
}
