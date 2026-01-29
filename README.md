![Conch](https://raw.githubusercontent.com/dend/conch/main/media/conch.png)

# Conch

A library to help authenticate against Xbox services. Available for both **.NET** and **Node.js**.

> [!WARNING]
> **This library is provided for educational and personal use purposes only.** It comes with no guarantees, implied or otherwise.
>
> By using this library, you acknowledge and agree to the following:
>
> - You interact with Xbox Live APIs **at your own risk**
> - Microsoft and Xbox may ban, suspend, or restrict accounts that use unofficial or unsanctioned APIs and projects (such as this library)
> - I bear **no responsibility** for any account bans, restrictions, suspensions, or other consequences that may result from using this library
> - You accept **full responsibility** for how you choose to use this library and any actions taken with it

## About

Conch is an Xbox Live authentication library designed to handle the complexities of Microsoft's authentication flows. It was created to support [Grunt](https://github.com/dend/grunt), a command-line tool for interacting with Xbox Live services.

### Key Capabilities

- **OAuth 2.0 Authentication** - Generate authorization URLs and exchange codes for tokens
- **Token Management** - Request and refresh OAuth tokens with scope customization
- **Xbox Live User Tokens** - Acquire user authentication tickets
- **Device Tokens** - Generate device tokens with Proof-of-Possession signing
- **XSTS Tokens** - Request Xbox Live Security Token Service (XSTS) tokens
- **SISU Authentication** - Support for SISU (Sign-In/Sign-Up) authentication flows

## Installation

### .NET

Install via NuGet:

```shell
dotnet add package Den.Dev.Conch
```

Or via the Package Manager Console:

```powershell
Install-Package Den.Dev.Conch
```

### Node.js

Install via npm:

```shell
npm install @dendotdev/conch
```

## Quick Start

### .NET

```csharp
using Den.Dev.Conch.Authentication;

// Create the authentication client
var authClient = new XboxAuthenticationClient();

// Generate an authorization URL for the user to visit
string authUrl = authClient.GenerateAuthUrl(
    clientId: "your-client-id",
    redirectUrl: "your-redirect-url"
);

// After user authorization, exchange the code for an OAuth token
var oauthToken = await authClient.RequestOAuthToken(
    clientId: "your-client-id",
    authorizationCode: "code-from-redirect",
    redirectUrl: "your-redirect-url"
);

// Request a user token
var userToken = await authClient.RequestUserToken(oauthToken.AccessToken);

// Request an XSTS token
var xstsToken = await authClient.RequestXstsToken(userToken.Token);

// Assemble the Xbox Live 3.0 token for API calls
string xblToken = authClient.GetXboxLiveV3Token(
    xstsToken.DisplayClaims.Xui[0].UserHash,
    xstsToken.Token
);
```

### Node.js / TypeScript

```typescript
import { XboxAuthenticationClient } from '@dendotdev/conch';

// Create the authentication client
const authClient = new XboxAuthenticationClient();

// Generate an authorization URL for the user to visit
const authUrl = authClient.generateAuthUrl(
    'your-client-id',
    'your-redirect-url'
);

// After user authorization, exchange the code for an OAuth token
const oauthToken = await authClient.requestOAuthToken(
    'your-client-id',
    'code-from-redirect',
    'your-redirect-url'
);

// Request a user token
const userToken = await authClient.requestUserToken(oauthToken.access_token!);

// Request an XSTS token
const xstsToken = await authClient.requestXstsToken(userToken.Token!);

// Assemble the Xbox Live 3.0 token for API calls
const xblToken = authClient.getXboxLiveV3Token(
    userToken.DisplayClaims!.xui![0]!.uhs!,
    xstsToken.Token!
);
```

## SISU Authentication

For scenarios requiring device and title tokens:

### .NET

```csharp
// Request a device token
var deviceToken = await authClient.RequestDeviceToken();

// Initialize a SISU session
var sisuSession = await authClient.RequestSISUSession(
    appId: "your-app-id",
    titleId: "your-title-id",
    deviceToken: deviceToken.Token,
    offers: new List<string> { "your-offers" },
    redirectUri: "your-redirect-url"
);

// After user authorization, request SISU tokens
var sisuTokens = await authClient.RequestSISUTokens(
    deviceToken: deviceToken.Token,
    accessToken: "access-token-from-oauth",
    appId: "your-app-id",
    sessionId: sisuSession.SessionId
);
```

### Node.js / TypeScript

```typescript
// Request a device token
const deviceToken = await authClient.requestDeviceToken();

// Initialize a SISU session
const sisuSession = await authClient.requestSISUSession(
    'your-app-id',
    'your-title-id',
    deviceToken.Token!,
    ['your-offers'],
    'your-redirect-url'
);

// After user authorization, request SISU tokens
const sisuTokens = await authClient.requestSISUTokens(
    deviceToken.Token!,
    'access-token-from-oauth',
    'your-app-id',
    sisuSession.SessionId
);
```

## Documentation

For detailed Node.js/TypeScript API documentation, see the [Node.js README](src/node/README.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to this project.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
