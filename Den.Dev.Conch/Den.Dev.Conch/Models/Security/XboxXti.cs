// <copyright file="XboxXti.cs" company="Den Delimarsky">
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
    public class XboxXti
    {
        /// <summary>
        /// Gets or sets the title ID.
        /// </summary>
        [JsonPropertyName("tid")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? TID { get; set; }
    }
}
