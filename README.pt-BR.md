# Cyphra OPAQUE.Net

Autenticação segura por senha para .NET usando o [protocolo OPAQUE](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/).

Este projeto é um fork do [Vaultic-LLC/OPAQUE.Net](https://github.com/Vaultic-LLC/OPAQUE.Net). O objetivo é melhorar a biblioteca, mantê-la ativamente e fortalecer sua segurança ao longo do tempo.

OPAQUE é um protocolo de troca de chaves autenticada por senha: o servidor consegue autenticar o usuário sem conhecer a senha, e os dois lados derivam uma chave de sessão após o login. A implementação combina uma API .NET com uma biblioteca nativa em Rust.

## Início rápido

Instale o pacote NuGet:

```sh
dotnet add package Vaultic.OPAQUE.Net
```

Use um `OpaqueServer` e um `OpaqueClient` para realizar o cadastro uma vez e repita o fluxo de login sempre que o usuário for autenticado:

```csharp
using OPAQUE.Net;
using OPAQUE.Net.Types.Results;

var server = new OpaqueServer();
var client = new OpaqueClient();

// Gere uma vez e armazene com segurança. Protege a chave de longo prazo do servidor.
server.CreateSetup(out string? serverSetup);

client.StartRegistration("senha forte do usuário",
    out StartClientRegistrationResult? registrationStart);

server.CreateRegistrationResponse(
    serverSetup!, "usuario-123", registrationStart!.RegistrationRequest,
    out string? registrationResponse);

client.FinishRegistration(
    "senha forte do usuário", registrationResponse!,
    registrationStart.ClientRegistrationState,
    out FinishClientRegistrationResult? registrationFinish);

// Armazene registrationFinish.RegistrationRecord junto da conta do usuário.
```

Para o fluxo completo de registro e login, resultados, identificadores, parâmetros Argon2id, builds nativos e orientações de segurança, consulte a [documentação em português](docs/README.pt-BR.md).

## Plataformas suportadas

O pacote usa .NET 8 e inclui bibliotecas nativas para Windows, Linux e macOS, nas arquiteturas x64 e arm64.

## Contribuição e segurança

- Leia [`CONTRIBUTING.md`](CONTRIBUTING.md) antes de abrir um pull request.
- Reporte vulnerabilidades de forma privada conforme [`docs/security.md`](docs/security.md).
- A documentação técnica está disponível em [`docs/`](docs/README.pt-BR.md).

## Licença

Consulte [`LICENSE`](LICENSE).
