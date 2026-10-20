# Changelog

## 1.5.0

Stricter input validation. Inputs that were previously accepted or failed silently now throw before the native call:

- Passwords and identifiers containing `\0` or an unpaired surrogate throw `ArgumentException` (previously truncated or replaced with U+FFFD, so different inputs could collide).
- The 1024 limit for passwords and identifiers is measured in UTF-8 bytes; exceeding it throws `ArgumentOutOfRangeException` (previously a silent `false` for non-ASCII text). No Unicode normalization is applied: NFC and NFD are different passwords.
- `KSFConfig.Create(KSFConfigType.RfcDraftRecommended)` throws; use `CreateRfcDraftRecommended(true)`. Undefined enum values throw.
- `OpaqueServer.CreateRegistrationResponse` rejects registration requests with trailing bytes.
