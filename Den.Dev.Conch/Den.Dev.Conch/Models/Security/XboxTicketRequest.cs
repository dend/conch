// <copyright file="XboxTicketRequest.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Den.Dev.Conch.Models.Security
{
    /// <summary>
    /// Container for the Xbox Live authentication ticket request.
    /// </summary>
    public class XboxTicketRequest
    {
        /// <summary>
        /// Gets or sets the relying party for which tokens will be obtained.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? RelyingParty { get; set; }

        /// <summary>
        /// Gets or sets the type of token to be obtained.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? TokenType { get; set; }

        /// <summary>
        /// Gets or sets additional properties associated with the Xbox Live authentication ticket.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public XboxTicketProperties? Properties { get; set; }

        /// <summary>
        /// Gets or sets the application ID registered in AAD.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? AppId { get; set; }

        /// <summary>
        /// Gets or sets the device token.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? DeviceToken { get; set; }

        /// <summary>
        /// Gets or sets the available offers.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public List<string>? Offers { get; set; }

        /// <summary>
        /// Gets or sets the proof key.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public ProofKey? ProofKey { get; set; }

        /// <summary>
        /// Gets or sets the authentication query.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public AuthQuery? Query { get; set; }

        /// <summary>
        /// Gets or sets the redirect URI specified in the app registration.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? RedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the sandbox.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? Sandbox { get; set; }

        /// <summary>
        /// Gets or sets the title ID.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? TitleId { get; set; }

        /// <summary>
        /// Gets or sets the access token.
        /// </summary>
        /// <remarks>
        /// Usually needs an attached d= or t= prefix to make sure it's recognized. Property used for SISU authorization.
        /// </remarks>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? AccessToken { get; set; }

        /// <summary>
        /// Gets or sets the session ID.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? SessionId { get; set; }

        /// <summary>
        /// Gets or sets the site name.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? SiteName { get; set; }

        /// <summary>
        /// Gets or sets whether a modern gamertag is used.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public bool? UseModernGamertag { get; set; }
    }
}
