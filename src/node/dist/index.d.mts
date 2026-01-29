/**
 * Represents an Elliptic Curve proof key in JWK (JSON Web Key) format.
 * Used for Proof-of-Possession (PoP) authentication with Xbox Live services.
 */
interface ProofKey {
    /**
     * Key type. Always 'EC' for Elliptic Curve.
     */
    readonly kty: 'EC';
    /**
     * Algorithm. Always 'ES256' (ECDSA using P-256 and SHA-256).
     */
    readonly alg: 'ES256';
    /**
     * Curve identifier. Always 'P-256' (NIST P-256 curve).
     */
    readonly crv: 'P-256';
    /**
     * Key use. Always 'sig' for signing.
     */
    readonly use: 'sig';
    /**
     * X coordinate of the public key point, Base64URL encoded.
     */
    readonly x: string;
    /**
     * Y coordinate of the public key point, Base64URL encoded.
     */
    readonly y: string;
}
/**
 * Creates a ProofKey object from JWK X and Y coordinates.
 * @param x - X coordinate, Base64URL encoded.
 * @param y - Y coordinate, Base64URL encoded.
 * @returns A ProofKey object.
 */
declare function createProofKey(x: string, y: string): ProofKey;

/**
 * Interface for Proof-of-Possession cryptographic providers.
 */
interface IPoPCryptoProvider {
    /**
     * Gets the proof key containing the public key parameters.
     */
    getProofKey(): Promise<ProofKey>;
    /**
     * Signs data using the private key.
     * @param data - The data to sign.
     * @returns The ECDSA signature (IEEE P1363 format, 64 bytes for P-256).
     */
    sign(data: Uint8Array): Promise<Uint8Array>;
}
/**
 * ECDSA P-256 based Proof-of-Possession cryptographic provider.
 * Generates an ephemeral EC key pair and provides signing capabilities.
 */
declare class ECDsaPoPCryptoProvider implements IPoPCryptoProvider {
    private keyPair;
    private proofKey;
    /**
     * Gets or generates the proof key containing the public key parameters.
     * The key is lazily generated on first access.
     * @returns A ProofKey object with the public key's X and Y coordinates.
     */
    getProofKey(): Promise<ProofKey>;
    /**
     * Signs data using the ECDSA private key with SHA-256.
     * @param data - The data to sign.
     * @returns The signature in IEEE P1363 format (r || s, 64 bytes total).
     */
    sign(data: Uint8Array): Promise<Uint8Array>;
    /**
     * Ensures the key pair is generated. Generates a new P-256 key pair if not already present.
     */
    private ensureKeyPair;
}

/**
 * Represents an OAuth 2.0 token response from Microsoft identity services.
 */
interface OAuthToken {
    /**
     * The type of token (typically 'bearer').
     */
    token_type?: string;
    /**
     * Number of seconds until the access token expires.
     */
    expires_in?: number;
    /**
     * The scope of access granted by the token.
     */
    scope?: string;
    /**
     * The access token used for authentication.
     */
    access_token?: string;
    /**
     * The refresh token used to obtain new access tokens.
     */
    refresh_token?: string;
    /**
     * The user identifier associated with the token.
     */
    user_id?: string;
}
/**
 * Type guard to check if an object is a valid OAuthToken with an access token.
 */
declare function hasAccessToken(token: OAuthToken): token is OAuthToken & {
    access_token: string;
};
/**
 * Type guard to check if an object is a valid OAuthToken with a refresh token.
 */
declare function hasRefreshToken(token: OAuthToken): token is OAuthToken & {
    refresh_token: string;
};

/**
 * User identity claims from Xbox Live.
 */
interface XboxXui {
    /**
     * User hash (used in XBL3.0 authorization header).
     */
    uhs?: string;
    /**
     * Xbox User ID (XUID).
     */
    xid?: string;
    /**
     * Gamertag (display name).
     */
    gtg?: string;
    /**
     * Age group.
     */
    agg?: string;
    /**
     * User settings restrictions.
     */
    usr?: string;
    /**
     * User title restrictions.
     */
    utr?: string;
    /**
     * Privileges string.
     */
    prv?: string;
    /**
     * Modern gamertag.
     */
    mgt?: string;
    /**
     * Unique modern gamertag (with discriminator).
     */
    umg?: string;
}
/**
 * Device identity claims from Xbox Live.
 */
interface XboxXdi {
    /**
     * Device ID.
     */
    did?: string;
    /**
     * Device clock skew.
     */
    dcs?: string;
}
/**
 * Title (application/game) identity claims from Xbox Live.
 */
interface XboxXti {
    /**
     * Title ID.
     */
    tid?: string;
}
/**
 * Container for display claims returned in Xbox tickets.
 */
interface XboxDisplayClaims {
    /**
     * User identity claims. May be a single object or array.
     */
    xui?: XboxXui[];
    /**
     * Device identity claims.
     */
    xdi?: XboxXdi;
    /**
     * Title identity claims.
     */
    xti?: XboxXti;
}

/**
 * Represents an Xbox authentication ticket (token response).
 */
interface XboxTicket {
    /**
     * When the token was issued (ISO 8601 timestamp).
     */
    IssueInstant?: string;
    /**
     * When the token expires (ISO 8601 timestamp).
     */
    NotAfter?: string;
    /**
     * The actual token value.
     */
    Token?: string;
    /**
     * Claims associated with the token.
     */
    DisplayClaims?: XboxDisplayClaims;
}
/**
 * Type guard to check if an XboxTicket has a valid token.
 */
declare function hasToken(ticket: XboxTicket | null | undefined): ticket is XboxTicket & {
    Token: string;
};
/**
 * Extracts the user hash from an Xbox ticket's display claims.
 * @param ticket - The Xbox ticket to extract from.
 * @returns The user hash, or undefined if not present.
 */
declare function getUserHash(ticket: XboxTicket | null | undefined): string | undefined;

/**
 * MSA request parameters placeholder for SISU authentication.
 */
interface MSARequestParameters {
}
/**
 * Response from SISU authentication (session initialization).
 */
interface SISUAuthenticationResponse {
    /**
     * The OAuth redirect URL for user authentication.
     */
    MsaOauthRedirect?: string;
    /**
     * Additional MSA request parameters.
     */
    MsaRequestParameters?: MSARequestParameters;
    /**
     * Session ID (extracted from X-SessionId response header).
     */
    SessionId?: string;
}
/**
 * Response from SISU authorization (token acquisition).
 */
interface SISUAuthorizationResponse {
    /**
     * Device token.
     */
    DeviceToken?: string;
    /**
     * Title token.
     */
    TitleToken?: XboxTicket;
    /**
     * User token.
     */
    UserToken?: XboxTicket;
    /**
     * Authorization (XSTS) token.
     */
    AuthorizationToken?: XboxTicket;
    /**
     * Web page URL (for additional authentication steps).
     */
    WebPage?: string;
    /**
     * Sandbox identifier.
     */
    Sandbox?: string;
    /**
     * Whether modern gamertag is used.
     */
    UseModernGamertag?: boolean;
    /**
     * Authentication flow type.
     */
    Flow?: string;
    /**
     * Error code (HTTP status code on failure).
     */
    ErrorCode?: number;
    /**
     * Error message on failure.
     */
    ErrorMessage?: string;
}
/**
 * Type guard to check if a SISU authorization response indicates success.
 */
declare function isSISUAuthorizationSuccess(response: SISUAuthorizationResponse): response is SISUAuthorizationResponse & {
    AuthorizationToken: XboxTicket;
};
/**
 * Type guard to check if a SISU authorization response indicates failure.
 */
declare function isSISUAuthorizationError(response: SISUAuthorizationResponse): response is SISUAuthorizationResponse & {
    ErrorCode: number;
    ErrorMessage: string;
};

/**
 * Options for creating an XboxAuthenticationClient.
 */
interface XboxAuthenticationClientOptions {
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
declare class XboxAuthenticationClient {
    private readonly popCryptoProvider;
    private readonly fetchFn;
    private readonly codeVerifier;
    private readonly codeChallenge;
    /**
     * Creates a new Xbox authentication client.
     * @param options - Configuration options.
     */
    constructor(options?: XboxAuthenticationClientOptions);
    /**
     * Generates an OAuth 2.0 authorization URL for Microsoft login.
     *
     * @param clientId - The application's client ID.
     * @param redirectUrl - The redirect URL after authorization.
     * @param scopes - OAuth scopes. Defaults to Xbox Live signin scopes.
     * @param state - Optional state parameter for CSRF protection.
     * @returns The authorization URL to redirect the user to.
     */
    generateAuthUrl(clientId: string, redirectUrl: string, scopes?: readonly string[], state?: string): string;
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
    requestOAuthToken(clientId: string, authorizationCode: string, redirectUrl: string, clientSecret?: string, scopes?: readonly string[], useCodeVerifier?: boolean, signal?: AbortSignal): Promise<OAuthToken | null>;
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
    refreshOAuthToken(clientId: string, refreshToken: string, redirectUrl: string, clientSecret?: string, scopes?: readonly string[], signal?: AbortSignal): Promise<OAuthToken | null>;
    /**
     * Requests a user authentication token from Xbox Live.
     *
     * @param accessToken - The OAuth access token.
     * @param signal - Optional AbortSignal for cancellation.
     * @returns The Xbox user ticket, or null on failure.
     */
    requestUserToken(accessToken: string, signal?: AbortSignal): Promise<XboxTicket | null>;
    /**
     * Formats an Xbox Live 3.0 authorization header value.
     *
     * @param userHash - The user hash from the user token's display claims.
     * @param userToken - The XSTS token value.
     * @returns The formatted authorization header value.
     */
    getXboxLiveV3Token(userHash: string, userToken: string): string;
    /**
     * Requests a device authentication token with Proof-of-Possession signature.
     *
     * @param deviceType - Device type (e.g., 'Win32', 'Android', 'iOS').
     * @param version - Device/OS version string.
     * @param authMethod - Authentication method (typically 'ProofOfPossession').
     * @param signal - Optional AbortSignal for cancellation.
     * @returns The Xbox device ticket, or null on failure.
     */
    requestDeviceToken(deviceType?: string, version?: string, authMethod?: string, signal?: AbortSignal): Promise<XboxTicket | null>;
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
    requestXstsToken(userToken: string, relyingParty?: "http://xboxlive.com", deviceToken?: string, titleToken?: string, signal?: AbortSignal): Promise<XboxTicket | null>;
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
    requestSISUSession(appId: string, titleId: string, deviceToken: string, offers: string[], redirectUri: string, tokenType?: string, sandbox?: string, signal?: AbortSignal): Promise<SISUAuthenticationResponse | null>;
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
    requestSISUTokens(deviceToken: string, accessToken: string, appId: string, sessionId?: string, sandbox?: string, siteName?: string, useModernGamertag?: boolean, signal?: AbortSignal): Promise<SISUAuthorizationResponse>;
    /**
     * Signs a request for Proof-of-Possession authentication.
     *
     * @param uri - The request URI.
     * @param authToken - The authorization token (empty string if none).
     * @param body - The request body.
     * @returns The Base64-encoded signature header value.
     */
    private signRequest;
    /**
     * Generates the signing payload for Proof-of-Possession.
     *
     * @param timestamp - Windows FILETIME timestamp.
     * @param uri - Request URI.
     * @param authToken - Authorization token.
     * @param body - Request body.
     * @returns The payload to sign.
     */
    private generateSigningPayload;
    /**
     * Gets the current time as a Windows FILETIME timestamp.
     * FILETIME is 100-nanosecond intervals since January 1, 1601.
     *
     * @returns The timestamp as a bigint.
     */
    private getWindowsTimestamp;
    /**
     * Generates a PKCE code verifier.
     * Creates a 32-byte random value and Base64URL encodes it.
     *
     * @returns The code verifier string.
     */
    private generateCodeVerifier;
    /**
     * Generates a PKCE code challenge from a verifier.
     * Computes SHA-256 hash of the verifier and Base64URL encodes it.
     *
     * @param verifier - The code verifier.
     * @returns The code challenge string.
     */
    private generateCodeChallenge;
    /**
     * Normalizes ticket display claims to ensure xui is always an array.
     *
     * @param ticket - The ticket to normalize.
     * @returns The ticket with normalized claims.
     */
    private normalizeTicketClaims;
}

/**
 * Properties for an Xbox ticket request.
 */
interface XboxTicketProperties {
    /**
     * Authentication method (e.g., 'RPS', 'ProofOfPossession').
     */
    AuthMethod?: string;
    /**
     * Site name for authentication.
     */
    SiteName?: string;
    /**
     * RPS ticket (OAuth access token with prefix).
     */
    RpsTicket?: string;
    /**
     * List of user tokens for XSTS authorization.
     */
    UserTokens?: string[];
    /**
     * Sandbox identifier (e.g., 'RETAIL').
     */
    SandboxId?: string;
    /**
     * Whether to use modern gamertag format.
     */
    UseModernGamertag?: boolean;
    /**
     * Device type (e.g., 'Win32', 'Android', 'iOS').
     */
    DeviceType?: string;
    /**
     * Device identifier (GUID format).
     */
    Id?: string;
    /**
     * Proof key for PoP authentication.
     */
    ProofKey?: ProofKey;
    /**
     * Device serial number.
     */
    SerialNumber?: string;
    /**
     * OS/device version.
     */
    Version?: string;
    /**
     * Device token for XSTS/SISU requests.
     */
    DeviceToken?: string;
    /**
     * Title token for XSTS requests.
     */
    TitleToken?: string;
}
/**
 * Query parameters for SISU authentication.
 */
interface AuthQuery {
    /**
     * Display mode hint.
     */
    display?: string;
    /**
     * PKCE code challenge.
     */
    code_challenge?: string;
    /**
     * Code challenge method (always 'S256').
     */
    code_challenge_method?: string;
    /**
     * Random state for CSRF protection.
     */
    state?: string;
}
/**
 * Request body for Xbox ticket operations.
 */
interface XboxTicketRequest {
    /**
     * Relying party identifier (e.g., 'http://xboxlive.com').
     */
    RelyingParty?: string;
    /**
     * Token type (typically 'JWT').
     */
    TokenType?: string;
    /**
     * Request properties.
     */
    Properties?: XboxTicketProperties;
    /**
     * Application ID for SISU authentication.
     */
    AppId?: string;
    /**
     * Device token for SISU authentication.
     */
    DeviceToken?: string;
    /**
     * List of offers for SISU authentication.
     */
    Offers?: string[];
    /**
     * Proof key for SISU authentication.
     */
    ProofKey?: ProofKey;
    /**
     * Query parameters for SISU authentication.
     */
    Query?: AuthQuery;
    /**
     * Redirect URI for SISU authentication.
     */
    RedirectUri?: string;
    /**
     * Sandbox for SISU authentication.
     */
    Sandbox?: string;
    /**
     * Title ID for SISU authentication.
     */
    TitleId?: string;
    /**
     * Access token for SISU authorization (with 't=' prefix).
     */
    AccessToken?: string;
    /**
     * Session ID for SISU authorization.
     */
    SessionId?: string;
    /**
     * Site name for SISU authorization.
     */
    SiteName?: string;
    /**
     * Whether to use modern gamertag format.
     */
    UseModernGamertag?: boolean;
}

/**
 * Xbox Live API endpoints for authentication and authorization.
 */
declare const XboxEndpoints: {
    /**
     * OAuth 2.0 authorization endpoint (Microsoft login).
     */
    readonly XboxLiveAuthorize: "https://login.live.com/oauth20_authorize.srf";
    /**
     * OAuth 2.0 token endpoint (Microsoft login).
     */
    readonly XboxLiveToken: "https://login.live.com/oauth20_token.srf";
    /**
     * Auth relying party identifier.
     */
    readonly XboxLiveAuthRelyingParty: "http://auth.xboxlive.com";
    /**
     * User authentication endpoint.
     */
    readonly XboxLiveUserAuthenticate: "https://user.auth.xboxlive.com/user/authenticate";
    /**
     * Standard Xbox Live relying party identifier.
     */
    readonly XboxLiveRelyingParty: "http://xboxlive.com";
    /**
     * XSTS token authorization endpoint.
     */
    readonly XboxLiveXstsAuthorize: "https://xsts.auth.xboxlive.com/xsts/authorize";
    /**
     * Device authentication endpoint (requires PoP signature).
     */
    readonly XboxLiveDeviceAuthenticate: "https://device.auth.xboxlive.com/device/authenticate";
    /**
     * SISU authentication endpoint (session initialization).
     */
    readonly XboxLiveSisuAuthenticate: "https://sisu.xboxlive.com/authenticate";
    /**
     * SISU authorization endpoint (token acquisition).
     */
    readonly XboxLiveSisuAuthorize: "https://sisu.xboxlive.com/authorize";
};
type XboxEndpoint = (typeof XboxEndpoints)[keyof typeof XboxEndpoints];

/**
 * URL-safe Base64 encoding utilities (RFC 4648 Section 5).
 * Uses the alphabet: A-Z, a-z, 0-9, -, _ (no padding).
 */
/**
 * Encodes a Uint8Array to URL-safe Base64 string (no padding).
 * @param data - The data to encode.
 * @returns URL-safe Base64 encoded string.
 */
declare function base64UrlEncode(data: Uint8Array): string;
/**
 * Decodes a URL-safe Base64 string to Uint8Array.
 * @param encoded - The URL-safe Base64 encoded string.
 * @returns Decoded data as Uint8Array.
 */
declare function base64UrlDecode(encoded: string): Uint8Array;
/**
 * Encodes a Uint8Array to standard Base64 string.
 * @param data - The data to encode.
 * @returns Standard Base64 encoded string.
 */
declare function base64Encode(data: Uint8Array): string;
/**
 * Decodes a standard Base64 string to Uint8Array.
 * @param encoded - The Base64 encoded string.
 * @returns Decoded data as Uint8Array.
 */
declare function base64Decode(encoded: string): Uint8Array;

/**
 * Default authentication scopes for Xbox Live.
 */
declare const DEFAULT_AUTH_SCOPES: readonly string[];
/**
 * Additional scope for device authentication with MBI_SSL.
 */
declare const DEVICE_AUTH_SCOPE = "service::user.auth.xboxlive.com::MBI_SSL";
/**
 * Default sandbox identifier.
 */
declare const DEFAULT_SANDBOX = "RETAIL";
/**
 * Default token type for Xbox authentication requests.
 */
declare const DEFAULT_TOKEN_TYPE = "JWT";
/**
 * Xbox Live contract version for user/XSTS endpoints.
 */
declare const CONTRACT_VERSION_V1 = "1";
/**
 * Xbox Live contract version for device/SISU endpoints.
 */
declare const CONTRACT_VERSION_V2 = "2";
/**
 * Policy version for request signing.
 */
declare const SIGNING_POLICY_VERSION = 1;

/**
 * Normalizes a value that may be a single item or an array to always be an array.
 * This handles API responses where a field may return either a single object or an array.
 *
 * @param value - The value to normalize (single item, array, null, or undefined).
 * @returns An array containing the item(s), or an empty array if the value is null/undefined.
 *
 * @example
 * normalizeToArray({ id: 1 }); // [{ id: 1 }]
 * normalizeToArray([{ id: 1 }, { id: 2 }]); // [{ id: 1 }, { id: 2 }]
 * normalizeToArray(null); // []
 * normalizeToArray(undefined); // []
 */
declare function normalizeToArray<T>(value: T | T[] | null | undefined): T[];
/**
 * Normalizes Xbox display claims to ensure xui is always an array.
 * Xbox APIs may return xui as a single object or an array depending on the request.
 *
 * @param claims - The raw display claims from the API.
 * @returns Normalized claims with xui as an array.
 */
declare function normalizeDisplayClaims<T extends {
    xui?: unknown;
}>(claims: T | null | undefined): (Omit<T, 'xui'> & {
    xui: T extends {
        xui?: infer U;
    } ? (U extends unknown[] ? U : U[]) : never;
}) | null;

export { type AuthQuery, CONTRACT_VERSION_V1, CONTRACT_VERSION_V2, DEFAULT_AUTH_SCOPES, DEFAULT_SANDBOX, DEFAULT_TOKEN_TYPE, DEVICE_AUTH_SCOPE, ECDsaPoPCryptoProvider, type IPoPCryptoProvider, type MSARequestParameters, type OAuthToken, type ProofKey, SIGNING_POLICY_VERSION, type SISUAuthenticationResponse, type SISUAuthorizationResponse, XboxAuthenticationClient, type XboxAuthenticationClientOptions, type XboxDisplayClaims, type XboxEndpoint, XboxEndpoints, type XboxTicket, type XboxTicketProperties, type XboxTicketRequest, type XboxXdi, type XboxXti, type XboxXui, base64Decode, base64Encode, base64UrlDecode, base64UrlEncode, createProofKey, getUserHash, hasAccessToken, hasRefreshToken, hasToken, isSISUAuthorizationError, isSISUAuthorizationSuccess, normalizeDisplayClaims, normalizeToArray };
