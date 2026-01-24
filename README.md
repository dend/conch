<div align="center">
  <img src="media/conch.png" alt="Conch" width="256" />
  <h1>Conch</h1>
  <p>A standalone C# library for Xbox Live authentication.</p>
</div>

## About

Conch is an Xbox Live authentication library designed to handle the complexities of Microsoft's authentication flows. It was created to support [Grunt](https://github.com/dend/grunt), a command-line tool for interacting with Xbox Live services.

### Key Capabilities

- **OAuth 2.0 Authentication** - Generate authorization URLs and exchange codes for tokens
- **Token Management** - Request and refresh OAuth tokens with scope customization
- **Xbox Live User Tokens** - Acquire user authentication tickets
- **Device Tokens** - Generate device tokens for XSTS authentication
- **XSTS Tokens** - Request Xbox Live Security Token Service (XSTS) tokens
- **SISU Authentication** - Support for SISU (Sign-In/Sign-Up) authentication flows
- **Proof-of-Possession (PoP) Signing** - Cryptographic request signing for secure API calls

## Disclaimer

> [!WARNING]
> **This library is provided for educational and personal purposes only.**
>
> By using this library, you acknowledge and agree to the following:
>
> - You interact with Xbox Live APIs **at your own risk**
> - Microsoft and Xbox may ban, suspend, or restrict accounts that use unofficial or unsanctioned APIs
> - The library author(s) bear **no responsibility** for any account bans, restrictions, suspensions, or other consequences that may result from using this library
> - You accept **full responsibility** for how you choose to use this library and any actions taken with it
>
> **Use responsibly and in accordance with Microsoft's Terms of Service.**

## Installation

Install via NuGet:

```shell
dotnet add package Den.Dev.Conch
```

Or via the Package Manager Console:

```powershell
Install-Package Den.Dev.Conch
```

## Quick Start

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

### Using SISU Authentication

For scenarios requiring device and title tokens:

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

## Error Handling

All authentication methods return `null` when they fail. Always check for null before using the result:

```csharp
var oauthToken = await authClient.RequestOAuthToken(clientId, code, redirectUrl);
if (oauthToken == null)
{
    // Handle authentication failure
    Console.WriteLine("Failed to obtain OAuth token");
    return;
}

var userToken = await authClient.RequestUserToken(oauthToken.AccessToken);
if (userToken == null)
{
    // Handle user token failure
    Console.WriteLine("Failed to obtain user token");
    return;
}

// Check token expiration before use
if (oauthToken.ExpiresIn <= 0)
{
    // Token may be expired, refresh it
    oauthToken = await authClient.RefreshOAuthToken(
        clientId,
        oauthToken.RefreshToken,
        redirectUrl
    );
}
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to this project.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
