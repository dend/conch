import type { XboxTicket } from './xbox-ticket.js';

/**
 * MSA request parameters placeholder for SISU authentication.
 */
export interface MSARequestParameters {
  // Reserved for future use
}

/**
 * Response from SISU authentication (session initialization).
 */
export interface SISUAuthenticationResponse {
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
export interface SISUAuthorizationResponse {
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
export function isSISUAuthorizationSuccess(
  response: SISUAuthorizationResponse
): response is SISUAuthorizationResponse & { AuthorizationToken: XboxTicket } {
  return response.AuthorizationToken !== undefined && response.ErrorCode === undefined;
}

/**
 * Type guard to check if a SISU authorization response indicates failure.
 */
export function isSISUAuthorizationError(
  response: SISUAuthorizationResponse
): response is SISUAuthorizationResponse & { ErrorCode: number; ErrorMessage: string } {
  return response.ErrorCode !== undefined && response.ErrorMessage !== undefined;
}
