import { createHash, randomBytes, webcrypto } from 'crypto';
import { ECDsaPoPCryptoProvider, type IPoPCryptoProvider } from './pop-crypto-provider.js';
import { XboxEndpoints } from '../endpoints/xbox-endpoints.js';
import {
  DEFAULT_AUTH_SCOPES,
  DEFAULT_SANDBOX,
  DEFAULT_TOKEN_TYPE,
  CONTRACT_VERSION_V1,
  CONTRACT_VERSION_V2,
  SIGNING_POLICY_VERSION,
} from '../util/xbox-auth-constants.js';
import { base64Encode, base64UrlEncode } from '../util/base64-encoder.js';
import { normalizeToArray } from '../converters/single-or-array.js';
import type { OAuthToken } from '../models/security/oauth-token.js';
import type { XboxTicket, XboxDisplayClaims } from '../models/security/xbox-ticket.js';
import type { XboxTicketRequest, XboxTicketProperties } from '../models/security/xbox-ticket-request.js';
import type { SISUAuthenticationResponse, SISUAuthorizationResponse } from '../models/security/sisu-responses.js';

/**
 * Options for creating an XboxAuthenticationClient.
 */
export interface XboxAuthenticationClientOptions {
  /**
   * Custom fetch function. Defaults to global fetch.
   */
  fetch?: typeof globalThis.fetch;

  /**
   * Custom Proof-of-Possession crypto provider.
   */
  popCryptoProvider?: IPoPCryptoProvider;
}

/**
 * Xbox Live authentication client.
 *
 * Provides methods for OAuth 2.0 authentication, Xbox Live user tokens,
 * device tokens with Proof-of-Possession, XSTS tokens, and SISU authentication.
 *
 * @example
 * ```typescript
 * const client = new XboxAuthenticationClient();
 *
 * // Generate OAuth authorization URL
 * const authUrl = client.generateAuthUrl('your-client-id', 'https://localhost/callback');
 *
 * // After user authorizes, exchange code for token
 * const oauthToken = await client.requestOAuthToken('your-client-id', authCode, 'https://localhost/callback');
 *
 * // Get user token
 * const userTicket = await client.requestUserToken(oauthToken.access_token!);
 *
 * // Get XSTS token
 * const xstsTicket = await client.requestXstsToken(userTicket.Token!);
 *
 * // Format for Xbox Live API calls
 * const authHeader = client.getXboxLiveV3Token(userTicket.DisplayClaims!.xui![0].uhs!, xstsTicket.Token!);
 * ```
 */
export class XboxAuthenticationClient {
  private readonly popCryptoProvider: IPoPCryptoProvider;
  private readonly fetchFn: typeof globalThis.fetch;
  private readonly codeVerifier: string;
  private readonly codeChallenge: string;

  /**
   * Creates a new Xbox authentication client.
   * @param options - Configuration options.
   */
  constructor(options: XboxAuthenticationClientOptions = {}) {
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
  generateAuthUrl(
    clientId: string,
    redirectUrl: string,
    scopes: readonly string[] = DEFAULT_AUTH_SCOPES,
    state?: string
  ): string {
    const url = new URL(XboxEndpoints.XboxLiveAuthorize);
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('approval_prompt', 'auto');
    url.searchParams.set('scope', scopes.join(' '));
    url.searchParams.set('redirect_uri', redirectUrl);
    url.searchParams.set('code_challenge', this.codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');

    if (state !== undefined) {
      url.searchParams.set('state', state);
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
  async requestOAuthToken(
    clientId: string,
    authorizationCode: string,
    redirectUrl: string,
    clientSecret?: string,
    scopes: readonly string[] = DEFAULT_AUTH_SCOPES,
    useCodeVerifier = true,
    signal?: AbortSignal
  ): Promise<OAuthToken | null> {
    const params = new URLSearchParams();
    params.set('grant_type', 'authorization_code');
    params.set('code', authorizationCode);
    params.set('scope', scopes.join(' '));
    params.set('redirect_uri', redirectUrl);
    params.set('client_id', clientId);

    if (clientSecret !== undefined) {
      params.set('client_secret', clientSecret);
    }

    if (useCodeVerifier) {
      params.set('code_verifier', this.codeVerifier);
    }

    const response = await this.fetchFn(XboxEndpoints.XboxLiveToken, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
      signal,
    });

    if (!response.ok) {
      return null;
    }

    return response.json() as Promise<OAuthToken>;
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
  async refreshOAuthToken(
    clientId: string,
    refreshToken: string,
    redirectUrl: string,
    clientSecret?: string,
    scopes: readonly string[] = DEFAULT_AUTH_SCOPES,
    signal?: AbortSignal
  ): Promise<OAuthToken | null> {
    const params = new URLSearchParams();
    params.set('grant_type', 'refresh_token');
    params.set('refresh_token', refreshToken);
    params.set('scope', scopes.join(' '));
    params.set('redirect_uri', redirectUrl);
    params.set('client_id', clientId);

    if (clientSecret !== undefined) {
      params.set('client_secret', clientSecret);
    }

    const response = await this.fetchFn(XboxEndpoints.XboxLiveToken, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
      signal,
    });

    if (!response.ok) {
      return null;
    }

    return response.json() as Promise<OAuthToken>;
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
  async requestUserToken(accessToken: string, signal?: AbortSignal): Promise<XboxTicket | null> {
    const request: XboxTicketRequest = {
      RelyingParty: XboxEndpoints.XboxLiveAuthRelyingParty,
      TokenType: DEFAULT_TOKEN_TYPE,
      Properties: {
        AuthMethod: 'RPS',
        SiteName: 'user.auth.xboxlive.com',
        RpsTicket: `d=${accessToken}`,
      },
    };

    const response = await this.fetchFn(XboxEndpoints.XboxLiveUserAuthenticate, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-xbl-contract-version': CONTRACT_VERSION_V1,
        Accept: 'application/json',
      },
      body: JSON.stringify(request),
      signal,
    });

    if (!response.ok) {
      return null;
    }

    const ticket = (await response.json()) as XboxTicket;
    return this.normalizeTicketClaims(ticket);
  }

  /**
   * Formats an Xbox Live 3.0 authorization header value.
   *
   * @param userHash - The user hash from the user token's display claims.
   * @param userToken - The XSTS token value.
   * @returns The formatted authorization header value.
   */
  getXboxLiveV3Token(userHash: string, userToken: string): string {
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
  async requestDeviceToken(
    deviceType = 'Win32',
    version = '10.0.22000',
    authMethod = 'ProofOfPossession',
    signal?: AbortSignal
  ): Promise<XboxTicket | null> {
    const deviceId = `{${webcrypto.randomUUID().toUpperCase()}}`;
    const proofKey = await this.popCryptoProvider.getProofKey();

    const request: XboxTicketRequest = {
      RelyingParty: XboxEndpoints.XboxLiveAuthRelyingParty,
      TokenType: DEFAULT_TOKEN_TYPE,
      Properties: {
        AuthMethod: authMethod,
        DeviceType: deviceType,
        Id: deviceId,
        ProofKey: proofKey,
        Version: version,
      },
    };

    const body = JSON.stringify(request);
    const signature = await this.signRequest(
      XboxEndpoints.XboxLiveDeviceAuthenticate,
      '',
      body
    );

    const response = await this.fetchFn(XboxEndpoints.XboxLiveDeviceAuthenticate, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        Signature: signature,
        'x-xbl-contract-version': CONTRACT_VERSION_V2,
      },
      body,
      signal,
    });

    if (!response.ok) {
      return null;
    }

    const ticket = (await response.json()) as XboxTicket;
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
  async requestXstsToken(
    userToken: string,
    relyingParty = XboxEndpoints.XboxLiveRelyingParty,
    deviceToken?: string,
    titleToken?: string,
    signal?: AbortSignal
  ): Promise<XboxTicket | null> {
    const properties: XboxTicketProperties = {
      UserTokens: [userToken],
      SandboxId: DEFAULT_SANDBOX,
    };

    if (deviceToken !== undefined) {
      properties.DeviceToken = deviceToken;
    }

    if (titleToken !== undefined) {
      properties.TitleToken = titleToken;
    }

    const request: XboxTicketRequest = {
      RelyingParty: relyingParty,
      TokenType: DEFAULT_TOKEN_TYPE,
      Properties: properties,
    };

    const response = await this.fetchFn(XboxEndpoints.XboxLiveXstsAuthorize, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-xbl-contract-version': CONTRACT_VERSION_V1,
        Accept: 'application/json',
      },
      body: JSON.stringify(request),
      signal,
    });

    if (!response.ok) {
      return null;
    }

    const ticket = (await response.json()) as XboxTicket;
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
  async requestSISUSession(
    appId: string,
    titleId: string,
    deviceToken: string,
    offers: string[],
    redirectUri: string,
    tokenType = 'code',
    sandbox = DEFAULT_SANDBOX,
    signal?: AbortSignal
  ): Promise<SISUAuthenticationResponse | null> {
    const proofKey = await this.popCryptoProvider.getProofKey();
    const state = webcrypto.randomUUID();

    const request: XboxTicketRequest = {
      AppId: appId,
      TitleId: titleId,
      DeviceToken: deviceToken,
      Offers: offers,
      ProofKey: proofKey,
      RedirectUri: redirectUri,
      Sandbox: sandbox,
      TokenType: tokenType,
      Query: {
        display: 'touch',
        code_challenge: this.codeChallenge,
        code_challenge_method: 'S256',
        state: state,
      },
    };

    const body = JSON.stringify(request);
    const signature = await this.signRequest(
      XboxEndpoints.XboxLiveSisuAuthenticate,
      '',
      body
    );

    const response = await this.fetchFn(XboxEndpoints.XboxLiveSisuAuthenticate, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        Signature: signature,
        'x-xbl-contract-version': CONTRACT_VERSION_V2,
      },
      body,
      signal,
    });

    if (!response.ok) {
      return null;
    }

    const authResponse = (await response.json()) as SISUAuthenticationResponse;

    // Extract session ID from response header
    const sessionId = response.headers.get('X-SessionId');
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
  async requestSISUTokens(
    deviceToken: string,
    accessToken: string,
    appId: string,
    sessionId?: string,
    sandbox = DEFAULT_SANDBOX,
    siteName = 'user.auth.xboxlive.com',
    useModernGamertag = true,
    signal?: AbortSignal
  ): Promise<SISUAuthorizationResponse> {
    const proofKey = await this.popCryptoProvider.getProofKey();

    const request: XboxTicketRequest = {
      AppId: appId,
      DeviceToken: deviceToken,
      ProofKey: proofKey,
      Sandbox: sandbox,
      AccessToken: `t=${accessToken}`,
      UseModernGamertag: useModernGamertag,
      SiteName: siteName,
    };

    if (sessionId !== undefined) {
      request.SessionId = sessionId;
    }

    const body = JSON.stringify(request);
    const signature = await this.signRequest(
      XboxEndpoints.XboxLiveSisuAuthorize,
      '',
      body
    );

    const response = await this.fetchFn(XboxEndpoints.XboxLiveSisuAuthorize, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        Signature: signature,
        'x-xbl-contract-version': CONTRACT_VERSION_V2,
      },
      body,
      signal,
    });

    if (!response.ok) {
      const errorText = await response.text();
      return {
        ErrorCode: response.status,
        ErrorMessage: errorText,
      };
    }

    const authzResponse = (await response.json()) as SISUAuthorizationResponse;

    // Normalize display claims in nested tickets
    if (authzResponse.UserToken !== undefined) {
      authzResponse.UserToken = this.normalizeTicketClaims(authzResponse.UserToken);
    }
    if (authzResponse.TitleToken !== undefined) {
      authzResponse.TitleToken = this.normalizeTicketClaims(authzResponse.TitleToken);
    }
    if (authzResponse.AuthorizationToken !== undefined) {
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
  private async signRequest(uri: string, authToken: string, body: string): Promise<string> {
    const timestamp = this.getWindowsTimestamp();
    const payload = this.generateSigningPayload(timestamp, uri, authToken, body);
    const signature = await this.popCryptoProvider.sign(payload);

    // Build final header: [policy version (4B)] + [timestamp (8B)] + [signature]
    const header = new Uint8Array(12 + signature.length);
    const view = new DataView(header.buffer);
    view.setUint32(0, SIGNING_POLICY_VERSION, false); // big-endian
    view.setBigUint64(4, timestamp, false); // big-endian
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
  private generateSigningPayload(
    timestamp: bigint,
    uri: string,
    authToken: string,
    body: string
  ): Uint8Array {
    const encoder = new TextEncoder();
    const url = new URL(uri);
    const pathAndQuery = url.pathname + url.search;

    // Build payload:
    // [policy version (4B BE)] + [0x00] +
    // [timestamp (8B BE)] + [0x00] +
    // "POST\0" + pathAndQuery + "\0" + authToken + "\0" + body + "\0"
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
    payload[offset++] = 0x00;
    payload.set(timestampBytes, offset);
    offset += timestampBytes.length;
    payload[offset++] = 0x00;
    payload.set(textPart, offset);

    return payload;
  }

  /**
   * Gets the current time as a Windows FILETIME timestamp.
   * FILETIME is 100-nanosecond intervals since January 1, 1601.
   *
   * @returns The timestamp as a bigint.
   */
  private getWindowsTimestamp(): bigint {
    const unixSeconds = BigInt(Math.floor(Date.now() / 1000));
    // Convert Unix epoch (1970-01-01) to Windows FILETIME epoch (1601-01-01)
    // Offset: 11644473600 seconds
    // Resolution: 100-nanosecond units (multiply by 10,000,000)
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
  private generateCodeVerifier(): string {
    const bytes = randomBytes(32);
    return base64UrlEncode(new Uint8Array(bytes));
  }

  /**
   * Generates a PKCE code challenge from a verifier.
   * Computes SHA-256 hash of the verifier and Base64URL encodes it.
   *
   * @param verifier - The code verifier.
   * @returns The code challenge string.
   */
  private generateCodeChallenge(verifier: string): string {
    const hash = createHash('sha256').update(verifier).digest();
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
  private normalizeTicketClaims(ticket: XboxTicket): XboxTicket {
    if (ticket.DisplayClaims !== undefined) {
      const claims = ticket.DisplayClaims as XboxDisplayClaims & { xui?: unknown };
      if (claims.xui !== undefined) {
        ticket.DisplayClaims = {
          ...claims,
          xui: normalizeToArray(claims.xui),
        } as XboxDisplayClaims;
      }
    }
    return ticket;
  }
}
