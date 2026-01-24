// <copyright file="XboxTicket.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

using System;

namespace Den.Dev.Conch.Models.Security
{
    /// <summary>
    /// Container class for the Xbox Live ticket.
    /// </summary>
    public class XboxTicket
    {
        /// <summary>
        /// Gets or sets the issuing time.
        /// </summary>
        public DateTime IssueInstant { get; set; }

        /// <summary>
        /// Gets or sets the expiration for the ticket.
        /// </summary>
        public DateTime NotAfter { get; set; }

        /// <summary>
        /// Gets or sets the Xbox Live access token.
        /// </summary>
        public string? Token { get; set; }

        /// <summary>
        /// Gets or sets the Xbox Live display claims for the authentication request.
        /// </summary>
        public XboxDisplayClaims? DisplayClaims { get; set; }
    }
}
