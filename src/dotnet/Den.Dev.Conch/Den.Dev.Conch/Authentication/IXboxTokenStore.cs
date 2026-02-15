// <copyright file="IXboxTokenStore.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

using Den.Dev.Conch.Models.Security;

namespace Den.Dev.Conch.Authentication
{
    /// <summary>
    /// Interface for storing and retrieving Xbox authentication tokens.
    /// </summary>
    public interface IXboxTokenStore
    {
        /// <summary>
        /// Loads the cached token data from storage.
        /// </summary>
        /// <returns>The cached token data, or null if no cache exists.</returns>
        XboxTokenCache? Load();

        /// <summary>
        /// Saves the token data to storage.
        /// </summary>
        /// <param name="cache">The token data to save.</param>
        void Save(XboxTokenCache cache);

        /// <summary>
        /// Clears any stored token data.
        /// </summary>
        void Clear();
    }
}
