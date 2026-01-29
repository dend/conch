/**
 * Default authentication scopes for Xbox Live.
 */
export const DEFAULT_AUTH_SCOPES: readonly string[] = [
  'Xboxlive.signin',
  'Xboxlive.offline_access',
] as const;

/**
 * Additional scope for device authentication with MBI_SSL.
 */
export const DEVICE_AUTH_SCOPE = 'service::user.auth.xboxlive.com::MBI_SSL';

/**
 * Default sandbox identifier.
 */
export const DEFAULT_SANDBOX = 'RETAIL';

/**
 * Default token type for Xbox authentication requests.
 */
export const DEFAULT_TOKEN_TYPE = 'JWT';

/**
 * Xbox Live contract version for user/XSTS endpoints.
 */
export const CONTRACT_VERSION_V1 = '1';

/**
 * Xbox Live contract version for device/SISU endpoints.
 */
export const CONTRACT_VERSION_V2 = '2';

/**
 * Policy version for request signing.
 */
export const SIGNING_POLICY_VERSION = 1;
