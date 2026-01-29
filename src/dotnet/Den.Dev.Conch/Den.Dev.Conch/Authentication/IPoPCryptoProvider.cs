// <copyright file="IPoPCryptoProvider.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

using Den.Dev.Conch.Models.Security;

namespace Den.Dev.Conch.Authentication
{
    /// <summary>
    /// Interface representing the Proof-of-Possession signature provider.
    /// </summary>
    public interface IPoPCryptoProvider
    {
        /// <summary>
        /// Gets the currently produced proof key for the provider.
        /// </summary>
        ProofKey ProofKey { get; }

        /// <summary>
        /// Signs the request data based on the existing key.
        /// </summary>
        /// <param name="data">Binary data to be signed.</param>
        /// <returns>If successful, returns data signed with the self-generated key.</returns>
        byte[] Sign(byte[] data);
    }
}
