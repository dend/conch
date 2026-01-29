/**
 * Xbox Live API endpoints for authentication and authorization.
 */
export const XboxEndpoints = {
  /**
   * OAuth 2.0 authorization endpoint (Microsoft login).
   */
  XboxLiveAuthorize: 'https://login.live.com/oauth20_authorize.srf',

  /**
   * OAuth 2.0 token endpoint (Microsoft login).
   */
  XboxLiveToken: 'https://login.live.com/oauth20_token.srf',

  /**
   * Auth relying party identifier.
   */
  XboxLiveAuthRelyingParty: 'http://auth.xboxlive.com',

  /**
   * User authentication endpoint.
   */
  XboxLiveUserAuthenticate: 'https://user.auth.xboxlive.com/user/authenticate',

  /**
   * Standard Xbox Live relying party identifier.
   */
  XboxLiveRelyingParty: 'http://xboxlive.com',

  /**
   * XSTS token authorization endpoint.
   */
  XboxLiveXstsAuthorize: 'https://xsts.auth.xboxlive.com/xsts/authorize',

  /**
   * Device authentication endpoint (requires PoP signature).
   */
  XboxLiveDeviceAuthenticate: 'https://device.auth.xboxlive.com/device/authenticate',

  /**
   * SISU authentication endpoint (session initialization).
   */
  XboxLiveSisuAuthenticate: 'https://sisu.xboxlive.com/authenticate',

  /**
   * SISU authorization endpoint (token acquisition).
   */
  XboxLiveSisuAuthorize: 'https://sisu.xboxlive.com/authorize',
} as const;

export type XboxEndpoint = (typeof XboxEndpoints)[keyof typeof XboxEndpoints];
