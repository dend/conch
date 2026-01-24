// <copyright file="XboxXdi.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

using System.Text.Json.Serialization;

namespace Den.Dev.Conch.Models.Security
{
    /// <summary>
    /// Container class encapsulating the Xbox device information.
    /// </summary>
    public class XboxXdi
    {
        /// <summary>
        /// Gets or sets the device ID.
        /// </summary>
        [JsonPropertyName("did")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? DID { get; set; }

        /// <summary>
        /// Gets or sets the device clock skew.
        /// </summary>
        [JsonPropertyName("dcs")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? DCS { get; set; }
    }
}
