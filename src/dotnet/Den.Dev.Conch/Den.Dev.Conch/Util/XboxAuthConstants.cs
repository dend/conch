// <copyright file="XboxAuthConstants.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

namespace Den.Dev.Conch.Util
{
    /// <summary>
    /// Constants used for Xbox Live authentication.
    /// </summary>
    public class XboxAuthConstants
    {
        /// <summary>
        /// Default scopes used for the Xbox Live authentication.
        /// </summary>
        /// <remarks>
        /// If device authentication is needed, you can use add `service::user.auth.xboxlive.com::MBI_SSL`.
        /// </remarks>
        public static readonly string[] DEFAULT_AUTH_SCOPES = new string[] { "Xboxlive.signin", "Xboxlive.offline_access" };
    }
}
