# Notification Service

[Leia em Portugues](README.pt-BR.md) | [Project root](../../README.md)

`role-notification` is the internal delivery service for email-based flows. It currently acts as a delivery worker and queue-backed HTTP endpoint for auth-related notifications.

## Current responsibilities

- accept trusted internal delivery requests
- queue delivery jobs
- deliver email verification and password reset messages
- support local outbox mode for development and smoke testing

## Security posture

- internal-token protected API
- encrypted on-disk queue
- production blocks plaintext outbox mode
- not intended to be exposed publicly

## Status

This service is intentionally small. It is good enough to support the current platform flows, but it is not yet a full notification platform. Template management, multiple providers, push channels, richer retries, and operator tooling are still future work.

