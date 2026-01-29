// <copyright file="AuthQuery.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

using System.Text.Json.Serialization;

namespace Den.Dev.Conch.Models.Security
{
    /// <summary>
    /// Container class for authentication query used for SISU flows.
    /// </summary>
    public class AuthQuery
    {
        /// <summary>
        /// Gets or sets the display string.
        /// </summary>
        [JsonPropertyName("display")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? Display { get; set; }

        /// <summary>
        /// Gets or sets the code challenge value.
        /// </summary>
        [JsonPropertyName("code_challenge")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? CodeChallenge { get; set; }

        /// <summary>
        /// Gets or sets the code challenge method.
        /// </summary>
        [JsonPropertyName("code_challenge_method")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? CodeChallengeMethod { get; set; }

        /// <summary>
        /// Gets or sets the state.
        /// </summary>
        [JsonPropertyName("state")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? State { get; set; }
    }
}
