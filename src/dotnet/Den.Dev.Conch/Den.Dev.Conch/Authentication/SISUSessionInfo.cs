// <copyright file="SISUSessionInfo.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

namespace Den.Dev.Conch.Authentication
{
    /// <summary>
    /// Holds intermediate state for a SISU authentication flow.
    /// The <see cref="AuthClient"/> instance must be preserved across the flow
    /// because the code verifier/challenge pair is generated per-instance.
    /// </summary>
    public class SISUSessionInfo
    {
        /// <summary>
        /// Gets or sets the OAuth redirect URL where the user authenticates.
        /// </summary>
        public string? OAuthUrl { get; set; }

        /// <summary>
        /// Gets or sets the SISU session ID from the X-SessionId response header.
        /// </summary>
        public string? SessionId { get; set; }

        /// <summary>
        /// Gets or sets the device token obtained during this flow.
        /// </summary>
        public string? DeviceToken { get; set; }

        /// <summary>
        /// Gets the authentication client instance that must be used to complete the flow.
        /// This is internal because callers should not access the client directly —
        /// the code verifier constraint requires the same instance across the entire flow.
        /// </summary>
        internal XboxAuthenticationClient? AuthClient { get; set; }
    }
}
