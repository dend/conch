// <copyright file="XboxTicketProperties.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

using System.Text.Json.Serialization;

namespace Den.Dev.Conch.Models.Security
{
    /// <summary>
    /// Container class for Xbox Live API ticket properties.
    /// </summary>
    public class XboxTicketProperties
    {
        /// <summary>
        /// Gets or sets the authentication method.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? AuthMethod { get; set; }

        /// <summary>
        /// Gets or sets the site name.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? SiteName { get; set; }

        /// <summary>
        /// Gets or sets the Relying Party Suite (RPS) ticket.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? RpsTicket { get; set; }

        /// <summary>
        /// Gets or sets the array of user tokens.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string[]? UserTokens { get; set; }

        /// <summary>
        /// Gets or sets the sandbox ID.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? SandboxId { get; set; }

        /// <summary>
        /// Gets or sets whether <see href="https://learn.microsoft.com/gaming/gdk/_content/gc/live/features/identity/user-profile/gamertags/live-modern-gamertags-overview">modern gamertag</see> format is used.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public bool? UseModernGamertag { get; set; }

        /// <summary>
        /// Gets or sets the device type for Proof-of-Possession authentication (used for device tokens).
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? DeviceType { get; set; }

        /// <summary>
        /// Gets or sets the device ID when generating a device token.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? Id { get; set; }

        /// <summary>
        /// Gets or sets the cryptographic proof key metadata.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public ProofKey? ProofKey { get; set; }

        /// <summary>
        /// Gets or sets the device serial number.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? SerialNumber { get; set; }

        /// <summary>
        /// Gets or sets the version of the OS on the device.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? Version { get; set; }

        /// <summary>
        /// Gets or sets the device token.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? DeviceToken { get; set; }

        /// <summary>
        /// Gets or sets the title token.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? TitleToken { get; set; }
    }
}
