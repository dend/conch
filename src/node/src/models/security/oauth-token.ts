/**
 * Represents an OAuth 2.0 token response from Microsoft identity services.
 */
export interface OAuthToken {
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
export function hasAccessToken(token: OAuthToken): token is OAuthToken & { access_token: string } {
  return typeof token.access_token === 'string' && token.access_token.length > 0;
}

/**
 * Type guard to check if an object is a valid OAuthToken with a refresh token.
 */
export function hasRefreshToken(token: OAuthToken): token is OAuthToken & { refresh_token: string } {
  return typeof token.refresh_token === 'string' && token.refresh_token.length > 0;
}
