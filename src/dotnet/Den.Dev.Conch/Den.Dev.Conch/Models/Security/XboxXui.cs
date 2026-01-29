// <copyright file="XboxXui.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

using System.Text.Json.Serialization;

namespace Den.Dev.Conch.Models.Security
{
    /// <summary>
    /// Xbox XUI
    /// </summary>
    public class XboxXui
    {
        /// <summary>
        /// Gets or sets the user hash.
        /// </summary>
        [JsonPropertyName("uhs")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? UserHash { get; set; }

        /// <summary>
        /// Gets or sets the user gamertag.
        /// </summary>
        [JsonPropertyName("gtg")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? Gamertag { get; set; }

        /// <summary>
        /// Gets or sets the user Xbox Live ID (XUID).
        /// </summary>
        [JsonPropertyName("xid")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? XUID { get; set; }

        /// <summary>
        /// Gets or sets the account age group.
        /// </summary>
        [JsonPropertyName("agg")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? AgeGroup { get; set; }

        /// <summary>
        /// Gets or sets the user settings restrictions.
        /// </summary>
        [JsonPropertyName("usr")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? UserSettingsRestrictions { get; set; }

        /// <summary>
        /// Gets or sets the user title restrictions.
        /// </summary>
        [JsonPropertyName("utr")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? UserTitleRestrictions { get; set; }

        /// <summary>
        /// Gets or sets the account privileges.
        /// </summary>
        [JsonPropertyName("prv")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? Privileges { get; set; }

        /// <summary>
        /// Gets or sets the modern gamertag.
        /// </summary>
        [JsonPropertyName("mgt")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? ModernGamertag { get; set; }

        /// <summary>
        /// Gets or sets the unique modern gamertag with the numbers appended to it, where appropriate.
        /// </summary>
        [JsonPropertyName("umg")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? UniqueModernGamertag { get; set; }
    }
}
