![Conch](conch.png)

# Den.Dev.Conch

An unofficial .NET library for Xbox Live authentication, not affiliated with or endorsed by Microsoft. Handles the complexities of Microsoft's OAuth, XSTS, and SISU authentication flows.

> [!WARNING]
> **This is an unofficial library provided for educational and personal use purposes only.** It is not affiliated with, endorsed by, or supported by Microsoft or Xbox. It comes with no guarantees, implied or otherwise.
>
> By using this library, you acknowledge and agree to the following:
>
> - You interact with Xbox Live APIs **at your own risk**
> - Microsoft and Xbox may ban, suspend, or restrict accounts that use unofficial or unsanctioned APIs and projects (such as this library)
> - I bear **no responsibility** for any account bans, restrictions, suspensions, or other consequences that may result from using this library
> - You accept **full responsibility** for how you choose to use this library and any actions taken with it

## Installation

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
string xblToken = XboxAuthenticationClient.FormatXboxLiveV3Token(
    xstsToken.DisplayClaims.Xui[0].UserHash,
    xstsToken.Token
);
```

## SISU Authentication

For scenarios requiring device and title tokens (e.g., Xbox capture APIs), use the high-level `SISUSessionManager` instead of manually wiring each step:

```csharp
using Den.Dev.Conch.Authentication;
using Den.Dev.Conch.Models.Security;

// Define your app's auth constants
var appConfig = new SISUAppConfiguration(
    AppId: "your-app-id",
    TitleId: "your-title-id",
    RedirectUri: "your-redirect-url",
    Scopes: new[] { "service::user.auth.xboxlive.com::MBI_SSL" }
);

// Provide a token store (see IXboxTokenStore section below)
IXboxTokenStore tokenStore = new JsonFileTokenStore("tokens.json");

var sessionManager = new SISUSessionManager(tokenStore, appConfig);

// Try to restore a previous session from stored refresh tokens
var cache = await sessionManager.TryRestoreSessionAsync();

if (cache == null)
{
    // No stored session — start a fresh login
    var session = await sessionManager.InitiateSISULoginAsync();

    // Direct the user to session.OAuthUrl, then capture the authorization code
    string code = /* code from OAuth redirect */;

    cache = await sessionManager.CompleteSISULoginAsync(session, code);
}

// Use the token for API calls
string authHeader = cache.AuthorizationHeaderValue;
```

### Automatic Token Refresh

`XboxTokenRefreshHandler` is a `DelegatingHandler` that intercepts 401 responses, refreshes tokens via `SISUSessionManager`, and retries the request:

```csharp
var handler = new XboxTokenRefreshHandler(sessionManager, tokenStore);
var httpClient = new HttpClient(handler);

// Requests through this HttpClient will automatically refresh on 401
```

### Implementing `IXboxTokenStore`

`SISUSessionManager` requires an `IXboxTokenStore` to persist tokens between sessions. The interface has three methods: `Load`, `Save`, and `Clear`. Here's a minimal JSON file-based implementation:

```csharp
using System.IO;
using System.Text.Json;
using Den.Dev.Conch.Authentication;
using Den.Dev.Conch.Models.Security;

public class JsonFileTokenStore : IXboxTokenStore
{
    private readonly string filePath;

    public JsonFileTokenStore(string filePath)
    {
        this.filePath = filePath;
    }

    public XboxTokenCache? Load()
    {
        if (!File.Exists(this.filePath))
        {
            return null;
        }

        var json = File.ReadAllText(this.filePath);
        return JsonSerializer.Deserialize<XboxTokenCache>(json);
    }

    public void Save(XboxTokenCache cache)
    {
        var json = JsonSerializer.Serialize(cache, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(this.filePath, json);
    }

    public void Clear()
    {
        if (File.Exists(this.filePath))
        {
            File.Delete(this.filePath);
        }
    }
}
```

> [!NOTE]
> This example stores tokens as plain-text JSON. For production use, use the built-in `EncryptedFileTokenStore` shown below, or a platform-specific credential store.

### Encrypted Token Storage

Conch includes `EncryptedFileTokenStore`, an AES-256-GCM encrypted implementation of `IXboxTokenStore`. By default it derives the encryption key from the machine name and user name, binding tokens to the current machine:

```csharp
using Den.Dev.Conch.Authentication;
using Den.Dev.Conch.Storage;

// Machine-bound encryption with default key derivation
IXboxTokenStore tokenStore = new EncryptedFileTokenStore("tokens.bin");

var sessionManager = new SISUSessionManager(tokenStore, appConfig);
```

You can also supply a custom passphrase for environments where the default machine-bound key isn't suitable:

```csharp
// Custom passphrase
IXboxTokenStore tokenStore = new EncryptedFileTokenStore(
    filePath: "tokens.bin",
    passphrase: "my-secret-passphrase"
);
```

## Low-Level SISU Flow

If you need full control over individual steps:

```csharp
var authClient = new XboxAuthenticationClient();

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

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/dend/conch/blob/main/LICENSE) file for details.
