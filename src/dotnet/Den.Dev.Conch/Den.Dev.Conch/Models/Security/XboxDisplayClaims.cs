// <copyright file="XboxDisplayClaims.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

using System.Collections.Generic;
using System.Text.Json.Serialization;
using Den.Dev.Conch.Converters;

namespace Den.Dev.Conch.Models.Security
{
    /// <summary>
    /// Container class for Xbox Live API display claims.
    /// </summary>
    public class XboxDisplayClaims
    {
        /// <summary>
        /// Gets or sets Xbox user-related information.
        /// </summary>
        [JsonPropertyName("xui")]
        [JsonConverter(typeof(SingleOrArrayJsonConverter<XboxXui>))]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public List<XboxXui>? Xui { get; set; }

        /// <summary>
        /// Gets or sets the Xbox device information.
        /// </summary>
        [JsonPropertyName("xdi")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public XboxXdi? Xdi { get; set; }

        /// <summary>
        /// Gets or sets the Xbox title information.
        /// </summary>
        [JsonPropertyName("xti")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public XboxXti? Xti { get; set; }
    }
}
