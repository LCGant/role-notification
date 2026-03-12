# Servico de Notification

[Read in English](README.md) | [Raiz do projeto](../../README.pt-BR.md)

`role-notification` e o servico interno de entrega para fluxos baseados em email. Hoje ele funciona como endpoint HTTP interno com fila para notificacoes do auth.

## Responsabilidades atuais

- aceitar pedidos internos confiaveis de entrega
- enfileirar jobs de entrega
- enviar mensagens de verificacao de email e reset de senha
- suportar modo outbox local para desenvolvimento e smoke testing

## Postura de seguranca

- API protegida por token interno
- fila em disco cifrada
- producao bloqueia modo plaintext de outbox
- nao deve ser exposto publicamente

## Estado atual

Este servico e pequeno de forma intencional. Ele ja atende os fluxos atuais da plataforma, mas ainda nao e uma plataforma completa de notificacao. Templates mais ricos, multiplos provedores, push, retries mais avancados e tooling operacional continuam como trabalho futuro.

