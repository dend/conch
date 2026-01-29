import type { ProofKey } from './proof-key.js';

/**
 * Properties for an Xbox ticket request.
 */
export interface XboxTicketProperties {
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
export interface AuthQuery {
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
export interface XboxTicketRequest {
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
