// <copyright file="ProofKey.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

using System.Text.Json.Serialization;

namespace Den.Dev.Conch.Models.Security
{
    /// <summary>
    /// Container class for the cryptographic proof key used for Proof-of-Possession requests.
    /// </summary>
    public class ProofKey
    {
        /// <summary>
        /// Gets or sets the elliptic curve.
        /// </summary>
        [JsonPropertyName("crv")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? Curve { get; set; }

        /// <summary>
        /// Gets or sets the algorithm.
        /// </summary>
        [JsonPropertyName("alg")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? Algorithm { get; set; }

        /// <summary>
        /// Gets or sets how the key should be used. "sig" represents the signature.
        /// </summary>
        [JsonPropertyName("use")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? Use { get; set; }

        /// <summary>
        /// Gets or sets the family of cryptographic algorithms used with the key.
        /// </summary>
        [JsonPropertyName("kty")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? KeyType { get; set; }

        /// <summary>
        /// Gets or sets the X coordinate for the Elliptic Curve point.
        /// </summary>
        [JsonPropertyName("x")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? X { get; set; }

        /// <summary>
        /// Gets or sets the Y coordinate for the Elliptic Curve point.
        /// </summary>
        [JsonPropertyName("y")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public string? Y { get; set; }
    }
}
