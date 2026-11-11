# Cyphra OPAQUE.Net

Autenticação segura por senha para .NET usando o [protocolo OPAQUE](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/), conforme implementado pelo [opaque-ke](https://github.com/facebook/opaque-ke) 3.0 (draft-irtf-cfrg-opaque-16). Registros e mensagens não têm garantia de interoperar com outros drafts nem com a RFC publicada.

Este projeto é um fork do [Vaultic-LLC/OPAQUE.Net](https://github.com/Vaultic-LLC/OPAQUE.Net). O objetivo é melhorar a biblioteca, mantê-la ativamente e fortalecer sua segurança ao longo do tempo.

OPAQUE é um protocolo de troca de chaves autenticada por senha: o servidor consegue autenticar o usuário sem conhecer a senha, e os dois lados derivam uma chave de sessão após o login. A implementação combina uma API .NET com uma biblioteca nativa em Rust.

## Início rápido

Instale o pacote NuGet:

```sh
dotnet add package Cyphra.OPAQUE.Net
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

O pacote tem como alvo .NET 8 e .NET 10 e inclui bibliotecas nativas para Windows, Linux e macOS, nas arquiteturas x64 e arm64.

A biblioteca nativa correta é escolhida pelo runtime identifier do .NET. No Linux há suporte apenas a glibc: Alpine/musl (`linux-musl-*`) e outros identificadores como `win-x86` ou `linux-arm` não têm biblioteca nativa, e compilar para eles emite o aviso `OPAQUE001`. Veja [plataformas e builds](docs/building.md).

A biblioteca nativa é carregada somente dos diretórios que o host .NET resolveu para a aplicação (os assets `runtimes/<rid>/native` e os diretórios da aplicação e do assembly). Uma biblioteca ausente ou que não carrega lança `DllNotFoundException` listando os diretórios verificados; o caminho de busca do sistema operacional (`LD_LIBRARY_PATH`, `PATH`, diretório atual) nunca é consultado.

### Verificando uma versão

Cada pacote de release carrega uma procedência de build assinada. Verifique um `.nupkg` baixado com `gh attestation verify <arquivo>.nupkg -R samueltorres-io/cyphra.OPAQUE.Net`.

## Status do projeto

Este é um fork de segurança mantido ativamente. Mudanças que afetam criptografia, interoperabilidade nativa, serialização, tratamento de senhas ou runtimes suportados exigem testes e revisão cuidadosa. Esta biblioteca não substitui um modelo de ameaças nem uma revisão de segurança da aplicação.

## Contribuição e segurança

- Leia [`CONTRIBUTING.md`](CONTRIBUTING.md) antes de abrir um pull request.
- Reporte vulnerabilidades de forma privada conforme [`docs/security.md`](docs/security.md).
- A documentação técnica está disponível em [`docs/`](docs/README.pt-BR.md).

## Licença

Consulte [`LICENSE`](LICENSE).
