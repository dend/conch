// <copyright file="XboxEndpoints.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

namespace Den.Dev.Conch.Endpoints
{
    /// <summary>
    /// Container for all Xbox Live API authentication endpoints.
    /// </summary>
    public class XboxEndpoints
    {
        /// <summary>
        /// Endpoint for OAuth 2.0 authorization against a Microsoft account.
        /// </summary>
        public static readonly string XboxLiveAuthorize = "https://login.live.com/oauth20_authorize.srf";

        /// <summary>
        /// Endpoint for OAuth 2.0 token acquisition for a Microsoft account.
        /// </summary>
        public static readonly string XboxLiveToken = "https://login.live.com/oauth20_token.srf";

        /// <summary>
        /// Relying party specified in Xbox Live API authentication requests.
        /// </summary>
        public static readonly string XboxLiveAuthRelyingParty = "http://auth.xboxlive.com";

        /// <summary>
        /// Xbox Live user authentication endpoint.
        /// </summary>
        public static readonly string XboxLiveUserAuthenticate = "https://user.auth.xboxlive.com/user/authenticate";

        /// <summary>
        /// Relying party specified in Xbox Live API requests.
        /// </summary>
        public static readonly string XboxLiveRelyingParty = "http://xboxlive.com";

        /// <summary>
        /// Xbox Live authorization endpoint.
        /// </summary>
        public static readonly string XboxLiveXstsAuthorize = "https://xsts.auth.xboxlive.com/xsts/authorize";

        /// <summary>
        /// Device authentication endpoint.
        /// </summary>
        public static readonly string XboxLiveDeviceAuthenticate = "https://device.auth.xboxlive.com/device/authenticate";

        /// <summary>
        /// SISU authentication URL.
        /// </summary>
        public static readonly string XboxLiveSisuAuthenticate = "https://sisu.xboxlive.com/authenticate";

        /// <summary>
        /// SISU authorization URL.
        /// </summary>
        public static readonly string XboxLiveSisuAuthorize = "https://sisu.xboxlive.com/authorize";
    }
}
