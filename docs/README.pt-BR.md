# Documentação do Cyphra OPAQUE.Net

O Cyphra OPAQUE.Net é um wrapper para .NET 8 de uma implementação Rust do protocolo OPAQUE, que permite autenticação por senha sem que o servidor receba a senha em texto puro.

Este projeto é um fork do [Vaultic-LLC/OPAQUE.Net](https://github.com/Vaultic-LLC/OPAQUE.Net), criado para melhorar a biblioteca, mantê-la ativamente e reforçar sua segurança.

## Conteúdo

- [Uso e fluxo do protocolo](usage.md) — cadastro, login, identificadores, chaves e falhas;
- [Referência da API](api.md) — classes públicas, resultados e `KSFConfig`;
- [Arquitetura](architecture.md) — código gerenciado, Rust, FFI e bibliotecas nativas;
- [Build e testes](building.md) — plataformas, compilação e empacotamento;
- [Política de segurança](security.md) — comunicação de vulnerabilidades e requisitos de uso seguro.

Para a introdução rápida, consulte o [README em português](../README.pt-BR.md). A documentação principal está em inglês; os nomes de tipos e métodos permanecem em inglês porque fazem parte da API pública.
