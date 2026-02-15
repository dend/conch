// <copyright file="SISUAppConfiguration.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

namespace Den.Dev.Conch.Authentication
{
    /// <summary>
    /// Immutable configuration record holding per-application constants
    /// required by the SISU authentication flow.
    /// </summary>
    /// <param name="AppId">The Xbox Live application ID.</param>
    /// <param name="TitleId">The Xbox Live title ID.</param>
    /// <param name="RedirectUri">The OAuth redirect URI.</param>
    /// <param name="Scopes">The authentication scopes (offers) to request.</param>
    /// <param name="Sandbox">The Xbox Live sandbox. Defaults to "RETAIL".</param>
    /// <param name="TokenType">The OAuth token type. Defaults to "code".</param>
    public record SISUAppConfiguration(
        string AppId,
        string TitleId,
        string RedirectUri,
        string[] Scopes,
        string Sandbox = "RETAIL",
        string TokenType = "code");
}
