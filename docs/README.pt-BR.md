# Documentação do Cyphra OPAQUE.Net

O Cyphra OPAQUE.Net é um wrapper para .NET (`net8.0` e `net10.0`) de uma implementação Rust do protocolo OPAQUE, que permite autenticação por senha sem que o servidor receba a senha em texto puro.

Este projeto é um fork do [Vaultic-LLC/OPAQUE.Net](https://github.com/Vaultic-LLC/OPAQUE.Net), criado para melhorar a biblioteca, mantê-la ativamente e reforçar sua segurança. Vindo da 1.x? Leia antes o [guia de migração no changelog](../CHANGELOG.md#migrating-from-1x).

A documentação detalhada está em inglês; os nomes de tipos e métodos permanecem em inglês porque fazem parte da API pública. Para a introdução rápida, consulte o [README em português](../README.pt-BR.md).

## Por onde começar

| Quero… | Leia |
| --- | --- |
| Adicionar login OPAQUE à minha aplicação | [Uso e fluxo do protocolo](guide/usage.md), depois a [referência da API](reference/api.md) |
| Saber quais plataformas e runtimes são suportados | [Plataformas suportadas](guide/platforms.md) |
| Fazer o deploy com segurança | [Uso seguro e limites conhecidos](security/secure-use.md) |
| Reportar uma vulnerabilidade | [Política de segurança](security/policy.md) |
| Entender como .NET e Rust se conectam | [Arquitetura](development/architecture.md) |
| Compilar, testar ou adicionar uma plataforma | [Build e testes](development/building.md) |
| Publicar uma versão | [Empacotamento e releases](development/releasing.md) |

Fora de `docs/`: [CONTRIBUTING.md](../CONTRIBUTING.md) (fluxo de contribuição) e [CHANGELOG.md](../CHANGELOG.md) (histórico de versões e migrações). O mapa completo dos arquivos está no [índice em inglês](README.md#map).
