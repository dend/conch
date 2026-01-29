'use strict';

var crypto = require('crypto');

// src/authentication/xbox-authentication-client.ts

// src/models/security/proof-key.ts
function createProofKey(x, y) {
  return {
    kty: "EC",
    alg: "ES256",
    crv: "P-256",
    use: "sig",
    x,
    y
  };
}

// src/authentication/pop-crypto-provider.ts
var ECDsaPoPCryptoProvider = class {
  keyPair = null;
  proofKey = null;
  /**
   * Gets or generates the proof key containing the public key parameters.
   * The key is lazily generated on first access.
   * @returns A ProofKey object with the public key's X and Y coordinates.
   */
  async getProofKey() {
    if (this.proofKey === null) {
      await this.ensureKeyPair();
    }
    return this.proofKey;
  }
  /**
   * Signs data using the ECDSA private key with SHA-256.
   * @param data - The data to sign.
   * @returns The signature in IEEE P1363 format (r || s, 64 bytes total).
   */
  async sign(data) {
    await this.ensureKeyPair();
    const signature = await crypto.webcrypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      this.keyPair.privateKey,
      data
    );
    return new Uint8Array(signature);
  }
  /**
   * Ensures the key pair is generated. Generates a new P-256 key pair if not already present.
   */
  async ensureKeyPair() {
    if (this.keyPair !== null) {
      return;
    }
    this.keyPair = await crypto.webcrypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const jwk = await crypto.webcrypto.subtle.exportKey("jwk", this.keyPair.publicKey);
    if (!jwk.x || !jwk.y) {
      throw new Error("Failed to export public key coordinates");
    }
    this.proofKey = createProofKey(jwk.x, jwk.y);
  }
};

// src/endpoints/xbox-endpoints.ts
var XboxEndpoints = {
  /**
   * OAuth 2.0 authorization endpoint (Microsoft login).
   */
  XboxLiveAuthorize: "https://login.live.com/oauth20_authorize.srf",
  /**
   * OAuth 2.0 token endpoint (Microsoft login).
   */
  XboxLiveToken: "https://login.live.com/oauth20_token.srf",
  /**
   * Auth relying party identifier.
   */
  XboxLiveAuthRelyingParty: "http://auth.xboxlive.com",
  /**
   * User authentication endpoint.
   */
  XboxLiveUserAuthenticate: "https://user.auth.xboxlive.com/user/authenticate",
  /**
   * Standard Xbox Live relying party identifier.
   */
  XboxLiveRelyingParty: "http://xboxlive.com",
  /**
   * XSTS token authorization endpoint.
   */
  XboxLiveXstsAuthorize: "https://xsts.auth.xboxlive.com/xsts/authorize",
  /**
   * Device authentication endpoint (requires PoP signature).
   */
  XboxLiveDeviceAuthenticate: "https://device.auth.xboxlive.com/device/authenticate",
  /**
   * SISU authentication endpoint (session initialization).
   */
  XboxLiveSisuAuthenticate: "https://sisu.xboxlive.com/authenticate",
  /**
   * SISU authorization endpoint (token acquisition).
   */
  XboxLiveSisuAuthorize: "https://sisu.xboxlive.com/authorize"
};

// src/util/xbox-auth-constants.ts
var DEFAULT_AUTH_SCOPES = [
  "Xboxlive.signin",
  "Xboxlive.offline_access"
];
var DEVICE_AUTH_SCOPE = "service::user.auth.xboxlive.com::MBI_SSL";
var DEFAULT_SANDBOX = "RETAIL";
var DEFAULT_TOKEN_TYPE = "JWT";
var CONTRACT_VERSION_V1 = "1";
var CONTRACT_VERSION_V2 = "2";
var SIGNING_POLICY_VERSION = 1;

// src/util/base64-encoder.ts
function base64UrlEncode(data) {
  return Buffer.from(data).toString("base64url");
}
function base64UrlDecode(encoded) {
  return new Uint8Array(Buffer.from(encoded, "base64url"));
}
function base64Encode(data) {
  return Buffer.from(data).toString("base64");
}
function base64Decode(encoded) {
  return new Uint8Array(Buffer.from(encoded, "base64"));
}

// src/converters/single-or-array.ts
function normalizeToArray(value) {
  if (value === null || value === void 0) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
}
function normalizeDisplayClaims(claims) {
  if (claims === null || claims === void 0) {
    return null;
  }
  return {
    ...claims,
    xui: normalizeToArray(claims.xui)
  };
}

// src/authentication/xbox-authentication-client.ts
var XboxAuthenticationClient = class {
  popCryptoProvider;
  fetchFn;
  codeVerifier;
  codeChallenge;
  /**
   * Creates a new Xbox authentication client.
   * @param options - Configuration options.
   */
  constructor(options = {}) {
    this.popCryptoProvider = options.popCryptoProvider ?? new ECDsaPoPCryptoProvider();
    this.fetchFn = options.fetch ?? globalThis.fetch;
    this.codeVerifier = this.generateCodeVerifier();
    this.codeChallenge = this.generateCodeChallenge(this.codeVerifier);
  }
  // ============================================================================
  // OAuth Methods
  // ============================================================================
  /**
   * Generates an OAuth 2.0 authorization URL for Microsoft login.
   *
   * @param clientId - The application's client ID.
   * @param redirectUrl - The redirect URL after authorization.
   * @param scopes - OAuth scopes. Defaults to Xbox Live signin scopes.
   * @param state - Optional state parameter for CSRF protection.
   * @returns The authorization URL to redirect the user to.
   */
  generateAuthUrl(clientId, redirectUrl, scopes = DEFAULT_AUTH_SCOPES, state) {
    const url = new URL(XboxEndpoints.XboxLiveAuthorize);
    url.searchParams.set("client_id", clientId);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("approval_prompt", "auto");
    url.searchParams.set("scope", scopes.join(" "));
    url.searchParams.set("redirect_uri", redirectUrl);
    url.searchParams.set("code_challenge", this.codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
    if (state !== void 0) {
      url.searchParams.set("state", state);
    }
    return url.toString();
  }
  /**
   * Exchanges an authorization code for OAuth tokens.
   *
   * @param clientId - The application's client ID.
   * @param authorizationCode - The authorization code from the redirect.
   * @param redirectUrl - The redirect URL (must match the one used for authorization).
   * @param clientSecret - Optional client secret for confidential clients.
   * @param scopes - OAuth scopes.
   * @param useCodeVerifier - Whether to include the PKCE code verifier.
   * @param signal - Optional AbortSignal for cancellation.
   * @returns The OAuth token response, or null on failure.
   */
  async requestOAuthToken(clientId, authorizationCode, redirectUrl, clientSecret, scopes = DEFAULT_AUTH_SCOPES, useCodeVerifier = true, signal) {
    const params = new URLSearchParams();
    params.set("grant_type", "authorization_code");
    params.set("code", authorizationCode);
    params.set("scope", scopes.join(" "));
    params.set("redirect_uri", redirectUrl);
    params.set("client_id", clientId);
    if (clientSecret !== void 0) {
      params.set("client_secret", clientSecret);
    }
    if (useCodeVerifier) {
      params.set("code_verifier", this.codeVerifier);
    }
    const response = await this.fetchFn(XboxEndpoints.XboxLiveToken, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: params.toString(),
      signal
    });
    if (!response.ok) {
      return null;
    }
    return response.json();
  }
  /**
   * Refreshes an OAuth access token using a refresh token.
   *
   * @param clientId - The application's client ID.
   * @param refreshToken - The refresh token.
   * @param redirectUrl - The redirect URL.
   * @param clientSecret - Optional client secret for confidential clients.
   * @param scopes - OAuth scopes.
   * @param signal - Optional AbortSignal for cancellation.
   * @returns The new OAuth token response, or null on failure.
   */
  async refreshOAuthToken(clientId, refreshToken, redirectUrl, clientSecret, scopes = DEFAULT_AUTH_SCOPES, signal) {
    const params = new URLSearchParams();
    params.set("grant_type", "refresh_token");
    params.set("refresh_token", refreshToken);
    params.set("scope", scopes.join(" "));
    params.set("redirect_uri", redirectUrl);
    params.set("client_id", clientId);
    if (clientSecret !== void 0) {
      params.set("client_secret", clientSecret);
    }
    const response = await this.fetchFn(XboxEndpoints.XboxLiveToken, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: params.toString(),
      signal
    });
    if (!response.ok) {
      return null;
    }
    return response.json();
  }
  // ============================================================================
  // User Token Methods
  // ============================================================================
  /**
   * Requests a user authentication token from Xbox Live.
   *
   * @param accessToken - The OAuth access token.
   * @param signal - Optional AbortSignal for cancellation.
   * @returns The Xbox user ticket, or null on failure.
   */
  async requestUserToken(accessToken, signal) {
    const request = {
      RelyingParty: XboxEndpoints.XboxLiveAuthRelyingParty,
      TokenType: DEFAULT_TOKEN_TYPE,
      Properties: {
        AuthMethod: "RPS",
        SiteName: "user.auth.xboxlive.com",
        RpsTicket: `d=${accessToken}`
      }
    };
    const response = await this.fetchFn(XboxEndpoints.XboxLiveUserAuthenticate, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-xbl-contract-version": CONTRACT_VERSION_V1,
        Accept: "application/json"
      },
      body: JSON.stringify(request),
      signal
    });
    if (!response.ok) {
      return null;
    }
    const ticket = await response.json();
    return this.normalizeTicketClaims(ticket);
  }
  /**
   * Formats an Xbox Live 3.0 authorization header value.
   *
   * @param userHash - The user hash from the user token's display claims.
   * @param userToken - The XSTS token value.
   * @returns The formatted authorization header value.
   */
  getXboxLiveV3Token(userHash, userToken) {
    return `XBL3.0 x=${userHash};${userToken}`;
  }
  // ============================================================================
  // Device Token Methods
  // ============================================================================
  /**
   * Requests a device authentication token with Proof-of-Possession signature.
   *
   * @param deviceType - Device type (e.g., 'Win32', 'Android', 'iOS').
   * @param version - Device/OS version string.
   * @param authMethod - Authentication method (typically 'ProofOfPossession').
   * @param signal - Optional AbortSignal for cancellation.
   * @returns The Xbox device ticket, or null on failure.
   */
  async requestDeviceToken(deviceType = "Win32", version = "10.0.22000", authMethod = "ProofOfPossession", signal) {
    const deviceId = `{${crypto.webcrypto.randomUUID().toUpperCase()}}`;
    const proofKey = await this.popCryptoProvider.getProofKey();
    const request = {
      RelyingParty: XboxEndpoints.XboxLiveAuthRelyingParty,
      TokenType: DEFAULT_TOKEN_TYPE,
      Properties: {
        AuthMethod: authMethod,
        DeviceType: deviceType,
        Id: deviceId,
        ProofKey: proofKey,
        Version: version
      }
    };
    const body = JSON.stringify(request);
    const signature = await this.signRequest(
      XboxEndpoints.XboxLiveDeviceAuthenticate,
      "",
      body
    );
    const response = await this.fetchFn(XboxEndpoints.XboxLiveDeviceAuthenticate, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Signature: signature,
        "x-xbl-contract-version": CONTRACT_VERSION_V2
      },
      body,
      signal
    });
    if (!response.ok) {
      return null;
    }
    const ticket = await response.json();
    return this.normalizeTicketClaims(ticket);
  }
  // ============================================================================
  // XSTS Token Methods
  // ============================================================================
  /**
   * Requests an XSTS authorization token.
   *
   * @param userToken - The user token from requestUserToken.
   * @param relyingParty - The relying party identifier.
   * @param deviceToken - Optional device token for elevated permissions.
   * @param titleToken - Optional title token for game-specific permissions.
   * @param signal - Optional AbortSignal for cancellation.
   * @returns The XSTS ticket, or null on failure.
   */
  async requestXstsToken(userToken, relyingParty = XboxEndpoints.XboxLiveRelyingParty, deviceToken, titleToken, signal) {
    const properties = {
      UserTokens: [userToken],
      SandboxId: DEFAULT_SANDBOX
    };
    if (deviceToken !== void 0) {
      properties.DeviceToken = deviceToken;
    }
    if (titleToken !== void 0) {
      properties.TitleToken = titleToken;
    }
    const request = {
      RelyingParty: relyingParty,
      TokenType: DEFAULT_TOKEN_TYPE,
      Properties: properties
    };
    const response = await this.fetchFn(XboxEndpoints.XboxLiveXstsAuthorize, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-xbl-contract-version": CONTRACT_VERSION_V1,
        Accept: "application/json"
      },
      body: JSON.stringify(request),
      signal
    });
    if (!response.ok) {
      return null;
    }
    const ticket = await response.json();
    return this.normalizeTicketClaims(ticket);
  }
  // ============================================================================
  // SISU Methods
  // ============================================================================
  /**
   * Initiates a SISU authentication session.
   *
   * @param appId - The application ID.
   * @param titleId - The title ID.
   * @param deviceToken - The device token from requestDeviceToken.
   * @param offers - List of offer identifiers.
   * @param redirectUri - The redirect URI for OAuth.
   * @param tokenType - Token type (typically 'code').
   * @param sandbox - Sandbox identifier.
   * @param signal - Optional AbortSignal for cancellation.
   * @returns The SISU authentication response with OAuth redirect URL, or null on failure.
   */
  async requestSISUSession(appId, titleId, deviceToken, offers, redirectUri, tokenType = "code", sandbox = DEFAULT_SANDBOX, signal) {
    const proofKey = await this.popCryptoProvider.getProofKey();
    const state = crypto.webcrypto.randomUUID();
    const request = {
      AppId: appId,
      TitleId: titleId,
      DeviceToken: deviceToken,
      Offers: offers,
      ProofKey: proofKey,
      RedirectUri: redirectUri,
      Sandbox: sandbox,
      TokenType: tokenType,
      Query: {
        display: "touch",
        code_challenge: this.codeChallenge,
        code_challenge_method: "S256",
        state
      }
    };
    const body = JSON.stringify(request);
    const signature = await this.signRequest(
      XboxEndpoints.XboxLiveSisuAuthenticate,
      "",
      body
    );
    const response = await this.fetchFn(XboxEndpoints.XboxLiveSisuAuthenticate, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Signature: signature,
        "x-xbl-contract-version": CONTRACT_VERSION_V2
      },
      body,
      signal
    });
    if (!response.ok) {
      return null;
    }
    const authResponse = await response.json();
    const sessionId = response.headers.get("X-SessionId");
    if (sessionId !== null) {
      authResponse.SessionId = sessionId;
    }
    return authResponse;
  }
  /**
   * Exchanges SISU session for authentication tokens.
   *
   * @param deviceToken - The device token.
   * @param accessToken - The OAuth access token.
   * @param appId - The application ID.
   * @param sessionId - The session ID from requestSISUSession.
   * @param sandbox - Sandbox identifier.
   * @param siteName - Site name for authentication.
   * @param useModernGamertag - Whether to use modern gamertag format.
   * @param signal - Optional AbortSignal for cancellation.
   * @returns The SISU authorization response with tokens, or error info on failure.
   */
  async requestSISUTokens(deviceToken, accessToken, appId, sessionId, sandbox = DEFAULT_SANDBOX, siteName = "user.auth.xboxlive.com", useModernGamertag = true, signal) {
    const proofKey = await this.popCryptoProvider.getProofKey();
    const request = {
      AppId: appId,
      DeviceToken: deviceToken,
      ProofKey: proofKey,
      Sandbox: sandbox,
      AccessToken: `t=${accessToken}`,
      UseModernGamertag: useModernGamertag,
      SiteName: siteName
    };
    if (sessionId !== void 0) {
      request.SessionId = sessionId;
    }
    const body = JSON.stringify(request);
    const signature = await this.signRequest(
      XboxEndpoints.XboxLiveSisuAuthorize,
      "",
      body
    );
    const response = await this.fetchFn(XboxEndpoints.XboxLiveSisuAuthorize, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Signature: signature,
        "x-xbl-contract-version": CONTRACT_VERSION_V2
      },
      body,
      signal
    });
    if (!response.ok) {
      const errorText = await response.text();
      return {
        ErrorCode: response.status,
        ErrorMessage: errorText
      };
    }
    const authzResponse = await response.json();
    if (authzResponse.UserToken !== void 0) {
      authzResponse.UserToken = this.normalizeTicketClaims(authzResponse.UserToken);
    }
    if (authzResponse.TitleToken !== void 0) {
      authzResponse.TitleToken = this.normalizeTicketClaims(authzResponse.TitleToken);
    }
    if (authzResponse.AuthorizationToken !== void 0) {
      authzResponse.AuthorizationToken = this.normalizeTicketClaims(authzResponse.AuthorizationToken);
    }
    return authzResponse;
  }
  // ============================================================================
  // Request Signing
  // ============================================================================
  /**
   * Signs a request for Proof-of-Possession authentication.
   *
   * @param uri - The request URI.
   * @param authToken - The authorization token (empty string if none).
   * @param body - The request body.
   * @returns The Base64-encoded signature header value.
   */
  async signRequest(uri, authToken, body) {
    const timestamp = this.getWindowsTimestamp();
    const payload = this.generateSigningPayload(timestamp, uri, authToken, body);
    const signature = await this.popCryptoProvider.sign(payload);
    const header = new Uint8Array(12 + signature.length);
    const view = new DataView(header.buffer);
    view.setUint32(0, SIGNING_POLICY_VERSION, false);
    view.setBigUint64(4, timestamp, false);
    header.set(signature, 12);
    return base64Encode(header);
  }
  /**
   * Generates the signing payload for Proof-of-Possession.
   *
   * @param timestamp - Windows FILETIME timestamp.
   * @param uri - Request URI.
   * @param authToken - Authorization token.
   * @param body - Request body.
   * @returns The payload to sign.
   */
  generateSigningPayload(timestamp, uri, authToken, body) {
    const encoder = new TextEncoder();
    const url = new URL(uri);
    const pathAndQuery = url.pathname + url.search;
    const policyVersionBytes = new Uint8Array(4);
    new DataView(policyVersionBytes.buffer).setUint32(0, SIGNING_POLICY_VERSION, false);
    const timestampBytes = new Uint8Array(8);
    new DataView(timestampBytes.buffer).setBigUint64(0, timestamp, false);
    const textPart = encoder.encode(`POST\0${pathAndQuery}\0${authToken}\0${body}\0`);
    const payload = new Uint8Array(
      policyVersionBytes.length + 1 + timestampBytes.length + 1 + textPart.length
    );
    let offset = 0;
    payload.set(policyVersionBytes, offset);
    offset += policyVersionBytes.length;
    payload[offset++] = 0;
    payload.set(timestampBytes, offset);
    offset += timestampBytes.length;
    payload[offset++] = 0;
    payload.set(textPart, offset);
    return payload;
  }
  /**
   * Gets the current time as a Windows FILETIME timestamp.
   * FILETIME is 100-nanosecond intervals since January 1, 1601.
   *
   * @returns The timestamp as a bigint.
   */
  getWindowsTimestamp() {
    const unixSeconds = BigInt(Math.floor(Date.now() / 1e3));
    return (unixSeconds + 11644473600n) * 10000000n;
  }
  // ============================================================================
  // PKCE Utilities
  // ============================================================================
  /**
   * Generates a PKCE code verifier.
   * Creates a 32-byte random value and Base64URL encodes it.
   *
   * @returns The code verifier string.
   */
  generateCodeVerifier() {
    const bytes = crypto.randomBytes(32);
    return base64UrlEncode(new Uint8Array(bytes));
  }
  /**
   * Generates a PKCE code challenge from a verifier.
   * Computes SHA-256 hash of the verifier and Base64URL encodes it.
   *
   * @param verifier - The code verifier.
   * @returns The code challenge string.
   */
  generateCodeChallenge(verifier) {
    const hash = crypto.createHash("sha256").update(verifier).digest();
    return base64UrlEncode(new Uint8Array(hash));
  }
  // ============================================================================
  // Utilities
  // ============================================================================
  /**
   * Normalizes ticket display claims to ensure xui is always an array.
   *
   * @param ticket - The ticket to normalize.
   * @returns The ticket with normalized claims.
   */
  normalizeTicketClaims(ticket) {
    if (ticket.DisplayClaims !== void 0) {
      const claims = ticket.DisplayClaims;
      if (claims.xui !== void 0) {
        ticket.DisplayClaims = {
          ...claims,
          xui: normalizeToArray(claims.xui)
        };
      }
    }
    return ticket;
  }
};

// src/models/security/oauth-token.ts
function hasAccessToken(token) {
  return typeof token.access_token === "string" && token.access_token.length > 0;
}
function hasRefreshToken(token) {
  return typeof token.refresh_token === "string" && token.refresh_token.length > 0;
}

// src/models/security/xbox-ticket.ts
function hasToken(ticket) {
  return ticket !== null && ticket !== void 0 && typeof ticket.Token === "string" && ticket.Token.length > 0;
}
function getUserHash(ticket) {
  return ticket?.DisplayClaims?.xui?.[0]?.uhs;
}

// src/models/security/sisu-responses.ts
function isSISUAuthorizationSuccess(response) {
  return response.AuthorizationToken !== void 0 && response.ErrorCode === void 0;
}
function isSISUAuthorizationError(response) {
  return response.ErrorCode !== void 0 && response.ErrorMessage !== void 0;
}

exports.CONTRACT_VERSION_V1 = CONTRACT_VERSION_V1;
exports.CONTRACT_VERSION_V2 = CONTRACT_VERSION_V2;
exports.DEFAULT_AUTH_SCOPES = DEFAULT_AUTH_SCOPES;
exports.DEFAULT_SANDBOX = DEFAULT_SANDBOX;
exports.DEFAULT_TOKEN_TYPE = DEFAULT_TOKEN_TYPE;
exports.DEVICE_AUTH_SCOPE = DEVICE_AUTH_SCOPE;
exports.ECDsaPoPCryptoProvider = ECDsaPoPCryptoProvider;
exports.SIGNING_POLICY_VERSION = SIGNING_POLICY_VERSION;
exports.XboxAuthenticationClient = XboxAuthenticationClient;
exports.XboxEndpoints = XboxEndpoints;
exports.base64Decode = base64Decode;
exports.base64Encode = base64Encode;
exports.base64UrlDecode = base64UrlDecode;
exports.base64UrlEncode = base64UrlEncode;
exports.createProofKey = createProofKey;
exports.getUserHash = getUserHash;
exports.hasAccessToken = hasAccessToken;
exports.hasRefreshToken = hasRefreshToken;
exports.hasToken = hasToken;
exports.isSISUAuthorizationError = isSISUAuthorizationError;
exports.isSISUAuthorizationSuccess = isSISUAuthorizationSuccess;
exports.normalizeDisplayClaims = normalizeDisplayClaims;
exports.normalizeToArray = normalizeToArray;
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map