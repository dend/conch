# Conch - Xbox Live Authentication Library for Node.js

A TypeScript library for Xbox Live authentication, supporting OAuth 2.0, user tokens, device tokens with Proof-of-Possession (PoP), XSTS tokens, and SISU authentication flows.

## Features

- **Zero external dependencies** - Uses only Node.js built-in modules
- **Full TypeScript support** - Complete type definitions included
- **OAuth 2.0 with PKCE** - Secure authorization code flow
- **Multiple authentication flows**:
  - Standard OAuth + User Token + XSTS
  - Device Token with Proof-of-Possession (ECDSA P-256)
  - SISU (Sign-In/Sign-Up) for mobile/console apps
- **Modern Node.js** - Uses Web Crypto API, native Base64URL encoding

## Requirements

- Node.js 18.0.0 or higher

## Installation

```bash
npm install conch
```

## Quick Start

### Standard Authentication Flow

The most common flow for web applications:

```typescript
import { XboxAuthenticationClient } from 'conch';

const client = new XboxAuthenticationClient();

// 1. Generate authorization URL
const authUrl = client.generateAuthUrl(
  'your-client-id',
  'https://localhost:3000/callback'
);
// Redirect user to authUrl...

// 2. After user authorizes, exchange code for tokens
const oauthToken = await client.requestOAuthToken(
  'your-client-id',
  authorizationCode,
  'https://localhost:3000/callback'
);

if (!oauthToken?.access_token) {
  throw new Error('Failed to get OAuth token');
}

// 3. Get Xbox Live user token
const userTicket = await client.requestUserToken(oauthToken.access_token);

if (!userTicket?.Token) {
  throw new Error('Failed to get user token');
}

// 4. Get XSTS authorization token
const xstsTicket = await client.requestXstsToken(userTicket.Token);

if (!xstsTicket?.Token) {
  throw new Error('Failed to get XSTS token');
}

// 5. Create authorization header for Xbox Live API calls
const userHash = userTicket.DisplayClaims?.xui?.[0]?.uhs;
const authHeader = client.getXboxLiveV3Token(userHash!, xstsTicket.Token);

// Use authHeader as the Authorization header for Xbox Live API requests
// Example: fetch('https://profile.xboxlive.com/users/me/profile/settings', {
//   headers: { Authorization: authHeader }
// })
```

### SISU Authentication Flow

For mobile apps or scenarios requiring device tokens:

```typescript
import { XboxAuthenticationClient } from 'conch';

const client = new XboxAuthenticationClient();

// 1. Get device token (requires PoP signature)
const deviceTicket = await client.requestDeviceToken('Win32', '10.0.22000');

if (!deviceTicket?.Token) {
  throw new Error('Failed to get device token');
}

// 2. Start SISU session
const sisuSession = await client.requestSISUSession(
  'your-app-id',
  'your-title-id',
  deviceTicket.Token,
  ['your-offer-ids'],
  'https://localhost:3000/callback'
);

if (!sisuSession?.MsaOauthRedirect) {
  throw new Error('Failed to start SISU session');
}

// 3. Redirect user to sisuSession.MsaOauthRedirect for authentication
// After user completes OAuth, exchange the code for an access token

// 4. Complete SISU flow
const sisuTokens = await client.requestSISUTokens(
  deviceTicket.Token,
  oauthAccessToken,
  'your-app-id',
  sisuSession.SessionId
);

if (sisuTokens.ErrorCode) {
  throw new Error(`SISU failed: ${sisuTokens.ErrorMessage}`);
}

// sisuTokens now contains:
// - DeviceToken
// - UserToken
// - TitleToken
// - AuthorizationToken (XSTS)
```

### Refreshing Tokens

```typescript
const newToken = await client.refreshOAuthToken(
  'your-client-id',
  refreshToken,
  'https://localhost:3000/callback'
);
```

## API Reference

### XboxAuthenticationClient

The main client for Xbox Live authentication.

#### Constructor

```typescript
new XboxAuthenticationClient(options?: {
  fetch?: typeof globalThis.fetch;    // Custom fetch implementation
  popCryptoProvider?: IPoPCryptoProvider;  // Custom crypto provider
})
```

#### OAuth Methods

| Method | Description |
|--------|-------------|
| `generateAuthUrl(clientId, redirectUrl, scopes?, state?)` | Generates OAuth authorization URL |
| `requestOAuthToken(clientId, code, redirectUrl, clientSecret?, scopes?, useCodeVerifier?, signal?)` | Exchanges auth code for tokens |
| `refreshOAuthToken(clientId, refreshToken, redirectUrl, clientSecret?, scopes?, signal?)` | Refreshes access token |

#### Token Methods

| Method | Description |
|--------|-------------|
| `requestUserToken(accessToken, signal?)` | Gets Xbox Live user token |
| `requestDeviceToken(deviceType?, version?, authMethod?, signal?)` | Gets device token with PoP |
| `requestXstsToken(userToken, relyingParty?, deviceToken?, titleToken?, signal?)` | Gets XSTS authorization token |
| `getXboxLiveV3Token(userHash, xstsToken)` | Formats XBL3.0 authorization header |

#### SISU Methods

| Method | Description |
|--------|-------------|
| `requestSISUSession(appId, titleId, deviceToken, offers, redirectUri, tokenType?, sandbox?, signal?)` | Starts SISU authentication |
| `requestSISUTokens(deviceToken, accessToken, appId, sessionId?, sandbox?, siteName?, useModernGamertag?, signal?)` | Completes SISU and gets all tokens |

### Types

#### OAuthToken

```typescript
interface OAuthToken {
  token_type?: string;
  expires_in?: number;
  scope?: string;
  access_token?: string;
  refresh_token?: string;
  user_id?: string;
}
```

#### XboxTicket

```typescript
interface XboxTicket {
  IssueInstant?: string;
  NotAfter?: string;
  Token?: string;
  DisplayClaims?: XboxDisplayClaims;
}
```

#### XboxDisplayClaims

```typescript
interface XboxDisplayClaims {
  xui?: XboxXui[];  // User identity claims
  xdi?: XboxXdi;    // Device identity claims
  xti?: XboxXti;    // Title identity claims
}

interface XboxXui {
  uhs?: string;   // User hash
  xid?: string;   // Xbox User ID
  gtg?: string;   // Gamertag
  agg?: string;   // Age group
  prv?: string;   // Privileges
  mgt?: string;   // Modern gamertag
  umg?: string;   // Unique modern gamertag
}
```

#### SISUAuthorizationResponse

```typescript
interface SISUAuthorizationResponse {
  DeviceToken?: string;
  TitleToken?: XboxTicket;
  UserToken?: XboxTicket;
  AuthorizationToken?: XboxTicket;
  WebPage?: string;
  Sandbox?: string;
  UseModernGamertag?: boolean;
  Flow?: string;
  ErrorCode?: number;      // Present on failure
  ErrorMessage?: string;   // Present on failure
}
```

### Utility Functions

```typescript
import {
  hasAccessToken,     // Check if OAuthToken has access_token
  hasRefreshToken,    // Check if OAuthToken has refresh_token
  hasToken,           // Check if XboxTicket has Token
  getUserHash,        // Extract user hash from XboxTicket
  isSISUAuthorizationSuccess,  // Check if SISU succeeded
  isSISUAuthorizationError,    // Check if SISU failed
} from 'conch';
```

## Authentication Flow Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    STANDARD FLOW                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐      │
│  │  OAuth  │───>│  User   │───>│  XSTS   │───>│  Xbox   │      │
│  │  Token  │    │  Token  │    │  Token  │    │  APIs   │      │
│  └─────────┘    └─────────┘    └─────────┘    └─────────┘      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    SISU FLOW                                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐      │
│  │ Device  │───>│  SISU   │───>│  OAuth  │───>│  SISU   │      │
│  │ Token   │    │ Session │    │ Consent │    │ Tokens  │      │
│  └─────────┘    └─────────┘    └─────────┘    └─────────┘      │
│      │                                              │            │
│      └──────────────────────────────────────────────┘            │
│                    (with PoP signature)                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Endpoints Used

| Endpoint | Purpose |
|----------|---------|
| `login.live.com/oauth20_authorize.srf` | OAuth authorization |
| `login.live.com/oauth20_token.srf` | OAuth token exchange |
| `user.auth.xboxlive.com/user/authenticate` | User token |
| `device.auth.xboxlive.com/device/authenticate` | Device token (PoP) |
| `xsts.auth.xboxlive.com/xsts/authorize` | XSTS authorization |
| `sisu.xboxlive.com/authenticate` | SISU session start |
| `sisu.xboxlive.com/authorize` | SISU token acquisition |

## Cryptography

This library uses the following cryptographic primitives (all from Node.js built-in `crypto` module):

- **ECDSA P-256** - For Proof-of-Possession request signing
- **SHA-256** - For PKCE code challenge generation
- **Web Crypto API** - For key generation and signing

No external cryptographic dependencies are required.

## Error Handling

The library uses a nullable return pattern consistent with the original C# implementation:

- Methods return `null` on HTTP failure
- SISU authorization returns an object with `ErrorCode` and `ErrorMessage` on failure

```typescript
const userTicket = await client.requestUserToken(accessToken);
if (userTicket === null) {
  // Handle error - request failed
}

const sisuTokens = await client.requestSISUTokens(/* ... */);
if (sisuTokens.ErrorCode !== undefined) {
  console.error(`Error ${sisuTokens.ErrorCode}: ${sisuTokens.ErrorMessage}`);
}
```

## License

MIT
