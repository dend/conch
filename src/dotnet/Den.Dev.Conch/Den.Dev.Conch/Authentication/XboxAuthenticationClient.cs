// <copyright file="XboxAuthenticationClient.cs" company="Den Delimarsky">
// Developed by Den Delimarsky.
// Den Delimarsky licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// </copyright>

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Den.Dev.Conch.Endpoints;
using Den.Dev.Conch.Models.Security;
using Den.Dev.Conch.Util;

namespace Den.Dev.Conch.Authentication
{
    /// <summary>
    /// Xbox authentication client, used to provide the scaffolding to get the
    /// proper Xbox Live tokens.
    /// </summary>
    public class XboxAuthenticationClient
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNameCaseInsensitive = true,
        };

        private readonly ECDCertificatePoPCryptoProvider popCryptoProvider = new();
        private readonly HttpClient client;
        private readonly string codeVerifier;
        private readonly string codeChallenge;

        /// <summary>
        /// Initializes a new instance of the <see cref="XboxAuthenticationClient"/> class.
        /// </summary>
        /// <param name="httpClient">Optional HttpClient instance to use. If not provided, a new instance will be created.</param>
        public XboxAuthenticationClient(HttpClient? httpClient = null)
        {
            this.client = httpClient ?? new HttpClient();
            this.codeVerifier = GenerateCodeVerifier();
            this.codeChallenge = GenerateCodeChallenge(this.codeVerifier);
        }

        /// <summary>
        /// Generates the authentication URL that can be used to produce the temporary code
        /// for subsequent Xbox Live authentication flows.
        /// </summary>
        /// <param name="clientId">Client ID defined for the registered application in the Azure Portal.</param>
        /// <param name="redirectUrl">Redirect URL defined for the registered application in the Azure Portal.</param>
        /// <param name="scopes">A list of scopes used for authentication against the Xbox Live APIs.</param>
        /// <param name="state">Temporary state indicator.</param>
        /// <returns>Returns the full authentication URL that can be pasted in a web browser.</returns>
        public string GenerateAuthUrl(string clientId, string redirectUrl, string[]? scopes = null, string state = "")
        {
            NameValueCollection queryString = System.Web.HttpUtility.ParseQueryString(string.Empty);

            queryString.Add("client_id", clientId);
            queryString.Add("response_type", "code");
            queryString.Add("approval_prompt", "auto");

            if (scopes != null && scopes.Length > 0)
            {
                queryString.Add("scope", string.Join(" ", scopes));
            }
            else
            {
                queryString.Add("scope", string.Join(" ", XboxAuthConstants.DEFAULT_AUTH_SCOPES));
            }

            queryString.Add("redirect_uri", redirectUrl);

            if (!string.IsNullOrEmpty(state))
            {
                queryString.Add("state", state);
            }

            return XboxEndpoints.XboxLiveAuthorize + "?" + queryString.ToString();
        }

        /// <summary>
        /// Requests the OAuth token for the Xbox Live authentication flow.
        /// </summary>
        /// <param name="clientId">Client ID defined for the registered application in the Azure Portal.</param>
        /// <param name="authorizationCode">Authorization code provided by visiting the URL from the <see cref="GenerateAuthUrl"/> function.</param>
        /// <param name="redirectUrl">Redirect URL defined for the registered application in the Azure Portal.</param>
        /// <param name="clientSecret">Client secret defined for the registered application in the Azure Portal.</param>
        /// <param name="scopes">A list of scopes used for authentication against the Xbox Live APIs.</param>
        /// <param name="useCodeVerifier">Determines whether the code verifier should be used. If not using SISU flows, this can be ignored.</param>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <returns>If successful, returns an instance of <see cref="OAuthToken"/> representing the OAuth token used for authentication. Otherwise, returns null.</returns>
        public async Task<OAuthToken?> RequestOAuthToken(string clientId, string authorizationCode, string redirectUrl, string clientSecret = "", string[]? scopes = null, bool useCodeVerifier = false, CancellationToken cancellationToken = default)
        {
            Dictionary<string, string> tokenRequestContent = new()
            {
                { "grant_type", "authorization_code" },
                { "code", authorizationCode },
                { "approval_prompt", "auto" },
            };

            if (useCodeVerifier)
            {
                tokenRequestContent.Add("code_verifier", this.codeVerifier);
            }

            return await this.ExecuteOAuthTokenRequestAsync(tokenRequestContent, clientId, redirectUrl, clientSecret, scopes, cancellationToken);
        }

        /// <summary>
        /// Refreshes an existing OAuth token.
        /// </summary>
        /// <param name="clientId">Client ID defined for the registered application in the Azure Portal.</param>
        /// <param name="refreshToken">Refresh token obtained from a previous authorization flow.</param>
        /// <param name="redirectUrl">Redirect URL defined for the registered application in the Azure Portal.</param>
        /// <param name="clientSecret">Client secret defined for the registered application in the Azure Portal.</param>
        /// <param name="scopes">A list of scopes used for authentication against the Xbox Live APIs.</param>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <returns>If successful, returns an instance of <see cref="OAuthToken"/> representing the OAuth token used for authentication. Otherwise, returns null.</returns>
        public async Task<OAuthToken?> RefreshOAuthToken(string clientId, string refreshToken, string redirectUrl, string clientSecret = "", string[]? scopes = null, CancellationToken cancellationToken = default)
        {
            Dictionary<string, string> tokenRequestContent = new()
            {
                { "grant_type", "refresh_token" },
                { "refresh_token", refreshToken },
            };

            return await this.ExecuteOAuthTokenRequestAsync(tokenRequestContent, clientId, redirectUrl, clientSecret, scopes, cancellationToken);
        }

        /// <summary>
        /// Executes an OAuth token request with the provided parameters.
        /// </summary>
        private async Task<OAuthToken?> ExecuteOAuthTokenRequestAsync(
            Dictionary<string, string> tokenRequestContent,
            string clientId,
            string redirectUrl,
            string clientSecret,
            string[]? scopes,
            CancellationToken cancellationToken)
        {
            if (scopes != null && scopes.Length > 0)
            {
                tokenRequestContent.Add("scope", string.Join(" ", scopes));
            }
            else
            {
                tokenRequestContent.Add("scope", string.Join(" ", XboxAuthConstants.DEFAULT_AUTH_SCOPES));
            }

            tokenRequestContent.Add("redirect_uri", redirectUrl);
            tokenRequestContent.Add("client_id", clientId);

            if (!string.IsNullOrEmpty(clientSecret))
            {
                tokenRequestContent.Add("client_secret", clientSecret);
            }

            var response = await this.client.PostAsync(XboxEndpoints.XboxLiveToken, new FormUrlEncodedContent(tokenRequestContent), cancellationToken);

            return response.IsSuccessStatusCode
                ? JsonSerializer.Deserialize<OAuthToken>(await response.Content.ReadAsStringAsync(cancellationToken), JsonOptions)
                : null;
        }

        /// <summary>
        /// Requests a user token for Xbox Live API authentication.
        /// </summary>
        /// <param name="accessToken">Previously generated Xbox Live OAuth access token.</param>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <returns>If successful, returns an instance of <see cref="XboxTicket"/> representing the authentication ticket. Otherwise, returns null.</returns>
        public async Task<XboxTicket?> RequestUserToken(string accessToken, CancellationToken cancellationToken = default)
        {
            XboxTicketRequest ticketData = new()
            {
                RelyingParty = XboxEndpoints.XboxLiveAuthRelyingParty,
                TokenType = "JWT",
                Properties = new XboxTicketProperties()
                {
                    AuthMethod = "RPS",
                    SiteName = "user.auth.xboxlive.com",
                    RpsTicket = string.Concat("d=", accessToken),
                },
            };

            var request = new HttpRequestMessage()
            {
                RequestUri = new Uri(XboxEndpoints.XboxLiveUserAuthenticate),
                Method = HttpMethod.Post,
                Content = new StringContent(JsonSerializer.Serialize(ticketData), Encoding.UTF8, "application/json"),
            };

            request.Headers.Add("x-xbl-contract-version", "1");

            var response = await this.client.SendAsync(request, cancellationToken);
            var responseData = await response.Content.ReadAsStringAsync(cancellationToken);

            return response.IsSuccessStatusCode
                ? JsonSerializer.Deserialize<XboxTicket>(responseData, JsonOptions)
                : null;
        }

        /// <summary>
        /// Requests the Xbox Live Security Token (XSTS) token.
        /// </summary>
        /// <param name="userToken">Previously generated Xbox Live user token.</param>
        /// <param name="relyingParty">The relying party to use. If null or empty, defaults to Xbox Live relying party.</param>
        /// <param name="deviceToken">Optional device token, if available.</param>
        /// <param name="titleToken">Optional title token, if available.</param>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <returns>If successful, returns an instance of <see cref="XboxTicket"/> representing the authentication ticket. Otherwise, returns null.</returns>
        public async Task<XboxTicket?> RequestXstsToken(string userToken, string? relyingParty = null, string? deviceToken = null, string? titleToken = null, CancellationToken cancellationToken = default)
        {
            XboxTicketRequest ticketData = new();

            if (string.IsNullOrWhiteSpace(relyingParty))
            {
                ticketData.RelyingParty = XboxEndpoints.XboxLiveRelyingParty;
            }
            else
            {
                ticketData.RelyingParty = relyingParty;
            }

            ticketData.TokenType = "JWT";
            ticketData.Properties = new XboxTicketProperties()
            {
                UserTokens = new string[] { userToken },
                SandboxId = "RETAIL",
                DeviceToken = deviceToken,
                TitleToken = titleToken,
            };

            var data = JsonSerializer.Serialize(ticketData);

            var request = new HttpRequestMessage()
            {
                RequestUri = new Uri(XboxEndpoints.XboxLiveXstsAuthorize),
                Method = HttpMethod.Post,
                Content = new StringContent(data, Encoding.UTF8, "application/json"),
            };

            request.Headers.Add("x-xbl-contract-version", "1");

            var response = await this.client.SendAsync(request, cancellationToken);
            var responseData = await response.Content.ReadAsStringAsync(cancellationToken);

            return response.IsSuccessStatusCode
                ? JsonSerializer.Deserialize<XboxTicket>(responseData, JsonOptions)
                : null;
        }

        /// <summary>
        /// Assemble existing token pieces into a valid Xbox Live 3.0 token.
        /// </summary>
        /// <param name="userHash">User has for the authenticating Xbox Live user.</param>
        /// <param name="userToken">Previously generated Xbox Live user token.</param>
        /// <returns>The assembled Xbox Live 3.0 token string.</returns>
        public string GetXboxLiveV3Token(string userHash, string userToken)
        {
            return $"XBL3.0 x={userHash};{userToken}";
        }

        /// <summary>
        /// Generates a device token that can be used for XSTS token acquisition.
        /// </summary>
        /// <param name="deviceType">Type of device. Default is Win32.</param>
        /// <param name="version">OS version on the device. Default is 10.0.22000 for Windows 11.</param>
        /// <param name="authMethod">Authentication method used. Default is ProofOfPossession.</param>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <returns>If successful, returns an instance of <see cref="XboxTicket"/> that contains the device token. Otherwise, returns null.</returns>
        public async Task<XboxTicket?> RequestDeviceToken(string deviceType = "Win32", string version = "10.0.22000", string authMethod = "ProofOfPossession", CancellationToken cancellationToken = default)
        {
            XboxTicketRequest ticketData = new()
            {
                RelyingParty = "http://auth.xboxlive.com",
                TokenType = "JWT",
                Properties = new()
                {
                    DeviceType = deviceType,
                    Id = $"{{{Guid.NewGuid().ToString().ToUpper()}}}",
                    Version = version,
                    AuthMethod = authMethod,
                    ProofKey = this.popCryptoProvider.ProofKey,
                },
            };

            var rawBody = JsonSerializer.Serialize(ticketData);
            var body = new StringContent(rawBody, Encoding.UTF8, "application/json");

            var request = new HttpRequestMessage()
            {
                RequestUri = new Uri(XboxEndpoints.XboxLiveDeviceAuthenticate),
                Method = HttpMethod.Post,
                Content = body,
            };

            var signature = this.SignRequest(XboxEndpoints.XboxLiveDeviceAuthenticate, string.Empty, rawBody);

            request.Headers.Add("Accept", "application/json");
            request.Headers.Add("Signature", signature);
            request.Headers.Add("x-xbl-contract-version", "2");

            var response = await this.client.SendAsync(request, cancellationToken);
            var responseData = await response.Content.ReadAsStringAsync(cancellationToken);

            return response.IsSuccessStatusCode
                ? JsonSerializer.Deserialize<XboxTicket>(responseData, JsonOptions)
                : null;
        }

        /// <summary>
        /// Initializes a new SISU session.
        /// </summary>
        /// <param name="appId">Application ID.</param>
        /// <param name="titleId">Title ID.</param>
        /// <param name="deviceToken">Previously-generated device token.</param>
        /// <param name="offers">List of associated offers.</param>
        /// <param name="redirectUri">Redirect URI used for authentication.</param>
        /// <param name="tokenType">Token type. Default is "code".</param>
        /// <param name="sandbox">The sandbox to be used. Default is "RETAIL".</param>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <returns>If successful, returns an instance of <see cref="SISUAuthenticationResponse"/>. Otherwise, returns null.</returns>
        public async Task<SISUAuthenticationResponse?> RequestSISUSession(string appId, string titleId, string deviceToken, List<string> offers, string redirectUri, string tokenType = "code", string sandbox = "RETAIL", CancellationToken cancellationToken = default)
        {
            XboxTicketRequest ticketData = new()
            {
                AppId = appId,
                TitleId = titleId,
                DeviceToken = deviceToken,
                Sandbox = sandbox,
                TokenType = tokenType,
                Offers = offers,
                RedirectUri = redirectUri,
                Query = new()
                {
                    CodeChallenge = this.codeChallenge,
                    CodeChallengeMethod = "S256",
                    State = Guid.NewGuid().ToString(),
                },
            };

            var rawBody = JsonSerializer.Serialize(ticketData);
            var body = new StringContent(rawBody, Encoding.UTF8, "application/json");

            var request = new HttpRequestMessage()
            {
                RequestUri = new Uri(XboxEndpoints.XboxLiveSisuAuthenticate),
                Method = HttpMethod.Post,
                Content = body,
            };

            var signature = this.SignRequest(XboxEndpoints.XboxLiveSisuAuthenticate, string.Empty, rawBody);

            request.Headers.Add("Accept", "application/json");
            request.Headers.Add("Signature", signature);
            request.Headers.Add("x-xbl-contract-version", "2");

            var response = await this.client.SendAsync(request, cancellationToken);
            var responseData = await response.Content.ReadAsStringAsync(cancellationToken);

            SISUAuthenticationResponse? authResponse = null;

            if (response.IsSuccessStatusCode)
            {
                authResponse = JsonSerializer.Deserialize<SISUAuthenticationResponse>(responseData, JsonOptions);
                IEnumerable<string>? headerValues;
                if (response.Headers.TryGetValues("X-SessionId", out headerValues))
                {
                    if (authResponse != null)
                    {
                        authResponse.SessionId = headerValues.First();
                    }
                }
            }

            return authResponse;
        }

        /// <summary>
        /// Uses the SISU endpoint to authorize the user, device, and the title.
        /// </summary>
        /// <remarks>
        /// Under most conditions, this will not be used and instead standard XSTS authorization should be relied upon. However, when special permission tokens are needed (e.g., when using the lobby endpoints), this is the way.
        /// </remarks>
        /// <param name="deviceToken">Previously generated device token.</param>
        /// <param name="accessToken">Access token from the OAuth authentication endpoint.</param>
        /// <param name="appId">Application ID.</param>
        /// <param name="sessionId">Session ID from the SISU authentication request.</param>
        /// <param name="sandbox">Sandbox to be used. Default value is "RETAIL".</param>
        /// <param name="siteName">Site name to be used for the request. Default value is "user.auth.xboxlive.com".</param>
        /// <param name="useModernGamertag">Determines whether modern gamertags are used. Default value is true.</param>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <returns>If successful, returns an instance of <see cref="SISUAuthorizationResponse"/> that contains device, authorization, user, and title tokens. Otherwise, returns null.</returns>
        public async Task<SISUAuthorizationResponse?> RequestSISUTokens(string deviceToken, string accessToken, string appId, string? sessionId = null, string sandbox = "RETAIL", string siteName = "user.auth.xboxlive.com", bool useModernGamertag = true, CancellationToken cancellationToken = default)
        {
            XboxTicketRequest ticketData = new()
            {
                AppId = appId,
                DeviceToken = deviceToken,
                ProofKey = this.popCryptoProvider.ProofKey,
                Sandbox = sandbox,
                AccessToken = $"t={accessToken}",
                UseModernGamertag = useModernGamertag,
                SessionId = sessionId,
                SiteName = siteName,
            };

            var rawBody = JsonSerializer.Serialize(ticketData);
            var body = new StringContent(rawBody, Encoding.UTF8, "application/json");

            var request = new HttpRequestMessage()
            {
                RequestUri = new Uri(XboxEndpoints.XboxLiveSisuAuthorize),
                Method = HttpMethod.Post,
                Content = body,
            };

            var signature = this.SignRequest(XboxEndpoints.XboxLiveSisuAuthorize, string.Empty, rawBody);

            request.Headers.Add("Accept", "application/json");
            request.Headers.Add("Signature", signature);
            request.Headers.Add("x-xbl-contract-version", "2");

            var response = await this.client.SendAsync(request, cancellationToken);
            var responseData = await response.Content.ReadAsStringAsync(cancellationToken);

            return response.IsSuccessStatusCode
                ? (JsonSerializer.Deserialize<SISUAuthorizationResponse>(responseData, JsonOptions) ?? new SISUAuthorizationResponse())
                    with { ErrorCode = response.StatusCode, ErrorMessage = responseData }
                : new SISUAuthorizationResponse { ErrorCode = response.StatusCode, ErrorMessage = responseData };
        }

        private static byte[] GenerateSigningPayload(ulong windowsTimestamp, string uri, string token, string payload)
        {
            var pathAndQuery = new Uri(uri).PathAndQuery;

            var allocSize =
                4 + 1 +
                8 + 1 +
                4 + 1 +
                pathAndQuery.Length + 1 +
                token.Length + 1 +
                payload.Length + 1;
            var bytes = new byte[allocSize];

            var policyVersion = GetBigEndianBytes(1);
            Array.Copy(policyVersion, 0, bytes, 0, 4);

            var windowsTimestampBytes = GetBigEndianBytes(windowsTimestamp);
            Array.Copy(windowsTimestampBytes, 0, bytes, 5, 8);

            var strs =
                $"POST\0" +
                $"{pathAndQuery}\0" +
                $"{token}\0" +
                $"{payload}\0";
            var strsBytes = Encoding.ASCII.GetBytes(strs);
            Array.Copy(strsBytes, 0, bytes, 14, strsBytes.Length);

            return bytes;
        }

        private static ulong GetWindowsTimestamp()
        {
            var unixTimestamp = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            ulong windowsTimestamp = (unixTimestamp + 11644473600u) * 10000000u;
            return windowsTimestamp;
        }

        private static byte[] GetBigEndianBytes(int value)
        {
            var bytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }

            return bytes;
        }

        private static byte[] GetBigEndianBytes(ulong value)
        {
            var bytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }

            return bytes;
        }

        private static string GenerateCodeVerifier()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var nonce = new char[32];
            for (int i = 0; i < nonce.Length; i++)
            {
                nonce[i] = chars[RandomNumberGenerator.GetInt32(chars.Length)];
            }

            return Base64Encoder.Encode(Encoding.UTF8.GetBytes(new string(nonce)));
        }

        private static string GenerateCodeChallenge(string codeVerifier)
        {
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
            return Convert.ToBase64String(hash)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');
        }

        private string SignRequest(string reqUri, string token, string body)
        {
            var timestamp = GetWindowsTimestamp();
            var data = GenerateSigningPayload(timestamp, reqUri, token, body);
            var signature = this.Sign(timestamp, data);
            return Convert.ToBase64String(signature);
        }

        private byte[] Sign(ulong windowsTimestamp, byte[] bytes)
        {
            var signature = this.popCryptoProvider.Sign(bytes);
            var policyVersion = GetBigEndianBytes(1);
            var windowsTimestampBytes = GetBigEndianBytes(windowsTimestamp);

            var header = new byte[signature.Length + 12];
            Array.Copy(policyVersion, 0, header, 0, 4);
            Array.Copy(windowsTimestampBytes, 0, header, 4, 8);
            Array.Copy(signature, 0, header, 12, signature.Length);

            return header;
        }
    }
}
