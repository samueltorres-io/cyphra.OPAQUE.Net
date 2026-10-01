# Usage and protocol flow

The public API is split into `OpaqueClient` and `OpaqueServer`. Each protocol message is represented by a string, while state values must be passed to the next step and must not be mixed between concurrent flows.

## Server setup

Create the server setup once:

```csharp
var server = new OpaqueServer();

if (!server.CreateSetup(out string? serverSetup) || serverSetup is null)
    throw new InvalidOperationException("Unable to create server setup.");
```

Store `serverSetup` in a secrets manager or equivalent protected storage. It is a long-term secret. A new setup produces a different server public key and makes old registration records unusable.

The corresponding public key can be obtained without exposing the setup secret:

```csharp
server.GetPublicKey(serverSetup, out string? serverPublicKey);
```

An application may pin or otherwise verify this public key at its own protocol boundary.

## Registration

Registration has three messages:

```csharp
var client = new OpaqueClient();
const string password = "user password";
const string userIdentifier = "user-123";

if (!client.StartRegistration(password,
    out StartClientRegistrationResult? start) || start is null)
    throw new InvalidOperationException("Client registration could not start.");

if (!server.CreateRegistrationResponse(
    serverSetup, userIdentifier, start.RegistrationRequest,
    out string? response) || response is null)
    throw new InvalidOperationException("Server registration could not start.");

if (!client.FinishRegistration(
    password, response, start.ClientRegistrationState,
    out FinishClientRegistrationResult? finish) || finish is null)
    throw new InvalidOperationException("Client registration could not finish.");

// Store with the account, never in logs:
string registrationRecord = finish.RegistrationRecord;
string exportKey = finish.ExportKey;
string serverStaticPublicKey = finish.ServerStaticPublicKey;
```

Only `registrationRecord` is required by the server for later login. The export key is client-side material and should be handled as a secret. The current API also exposes the server key through the legacy property `ServerStaicPublicKey` on `FinishClientRegistrationResult`; new code should prefer the correctly spelled login result property, while existing callers must account for this compatibility typo.

## Login

Login has four steps and produces the same session key on both sides:

```csharp
if (!client.StartLogin(password,
    out StartClientLoginResult? clientStart) || clientStart is null)
    throw new InvalidOperationException("Client login could not start.");

if (!server.StartLogin(
    serverSetup,
    clientStart.StartLoginRequest,
    userIdentifier,
    registrationRecord,
    out StartServerLoginResult? serverStart,
    out Exception? infrastructureError) || serverStart is null)
{
    throw new AuthenticationException("Login could not start.", infrastructureError);
}

if (!client.FinishLogin(
    clientStart.ClientLoginState,
    serverStart.LoginResponse,
    password,
    out FinishClientLoginResult? clientFinish) || clientFinish is null)
    throw new AuthenticationException("Invalid credentials.");

if (!server.FinishLogin(
    serverStart.ServerLoginState,
    clientFinish.FinishLoginRequest,
    out string? serverSessionKey) || serverSessionKey is null)
    throw new AuthenticationException("Login could not be completed.");

// clientFinish.SessionKey and serverSessionKey must be equal.
```

The overloads that accept `clientIdentifier` and `serverIdentifier` bind the exchange to additional context. Use stable, canonical values and pass exactly the same values during registration and login. A mismatch must fail authentication.

## Argon2id settings

The default `KSFConfig` is memory-constrained. Applications can select the RFC draft recommendation or a validated custom configuration:

```csharp
using OPAQUE.Net.Types.Parameters;

var recommended = KSFConfig.Create(KSFConfigType.RfcDraftRecommended);
var custom = KSFConfig.Create(
    KSFConfigType.Custom,
    iterations: 1,
    memory: 65536,
    parallelism: 4);
```

Use the same configuration for registration and login. Custom values are range-checked before the native call. The current limits are 1–10 iterations, 64 MiB–256 MiB memory, and parallelism 1–16. `RfcDraftRecommended` is an explicit compatibility choice and can require about 2 GiB; deploy it only where that per-request memory budget is available. Changing the configuration for existing records can make login fail, so treat it as part of the credential format and migration plan.

## Failure handling

Public methods return `false` and a null result when a native protocol operation fails. Empty required strings throw `StringParamIsEmptyException`; invalid custom KSF values throw `ArgumentOutOfRangeException`. Do not turn these outcomes into detailed authentication errors visible to remote users, because that can disclose account or protocol state.
