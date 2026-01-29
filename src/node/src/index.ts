// Authentication
export {
  XboxAuthenticationClient,
  type XboxAuthenticationClientOptions,
} from './authentication/xbox-authentication-client.js';
export {
  ECDsaPoPCryptoProvider,
  type IPoPCryptoProvider,
} from './authentication/pop-crypto-provider.js';

// Models
export {
  type ProofKey,
  createProofKey,
} from './models/security/proof-key.js';
export {
  type OAuthToken,
  hasAccessToken,
  hasRefreshToken,
} from './models/security/oauth-token.js';
export {
  type XboxXui,
  type XboxXdi,
  type XboxXti,
  type XboxDisplayClaims,
} from './models/security/xbox-display-claims.js';
export {
  type XboxTicket,
  hasToken,
  getUserHash,
} from './models/security/xbox-ticket.js';
export {
  type XboxTicketProperties,
  type AuthQuery,
  type XboxTicketRequest,
} from './models/security/xbox-ticket-request.js';
export {
  type MSARequestParameters,
  type SISUAuthenticationResponse,
  type SISUAuthorizationResponse,
  isSISUAuthorizationSuccess,
  isSISUAuthorizationError,
} from './models/security/sisu-responses.js';

// Endpoints
export { XboxEndpoints, type XboxEndpoint } from './endpoints/xbox-endpoints.js';

// Utilities
export {
  base64UrlEncode,
  base64UrlDecode,
  base64Encode,
  base64Decode,
} from './util/base64-encoder.js';
export {
  DEFAULT_AUTH_SCOPES,
  DEVICE_AUTH_SCOPE,
  DEFAULT_SANDBOX,
  DEFAULT_TOKEN_TYPE,
  CONTRACT_VERSION_V1,
  CONTRACT_VERSION_V2,
  SIGNING_POLICY_VERSION,
} from './util/xbox-auth-constants.js';

// Converters
export { normalizeToArray, normalizeDisplayClaims } from './converters/single-or-array.js';
