# Changelog

## 0.2.0

- Rebrand the federated plugin family from `biometric_storage` to
  `webauthn_secure_storage` across packages, folders, imports, docs, and
  platform metadata.
- Reset the fork changelog so future changes are tracked independently.
- Clean generated artifacts from the repository and refresh ignore rules for a
  cleaner Flutter package workspace.
- Clarify the recommended app integration workflow in the package README,
  including the distinction between platform support and biometric
  availability-at-runtime.
- Document platform-specific project setup requirements for Android, iOS,
  macOS, Linux, Windows, and web consumers.
- Improve Darwin biometric availability handling for macOS closed-clamshell and
  similar temporarily-unavailable authenticator states.
- Replace deprecated macOS Keychain prompt/UI query usage with modern
  `LAContext`-based configuration.
- Add native Windows passkey registration/authentication using Dart FFI against
  `webauthn.dll`, including real Windows Hello availability reporting.
- Add Linux desktop biometric-gated storage using `fprintd` and native passkey
  registration/authentication using `libfido2`.
- Extend Linux/Windows desktop tests and CI build dependencies to validate the
  new native desktop authentication flows.

### Data-migration note for Linux users

The libsecret schema name for new writes is now `"dev.webauthn_secure_storage"`.
To preserve upgrade compatibility, reads, existence checks, and deletes also
fall back to the upstream schema `"design.codeux.BiometricStorage"` and the
legacy key prefix when needed.

Existing Linux secrets remain readable after upgrade. They will continue to use
the legacy schema until they are re-written with this package.

### Data-migration note for Apple platforms

New writes now use the keychain service `"flutter_webauthn_secure_storage"`.
To preserve upgrade compatibility, reads, existence checks, and deletes also
fall back to the upstream keychain service `"flutter_biometric_storage"` when
needed.

Existing iOS and macOS secrets remain readable after upgrade. They will move to
the new service only after being re-written with this package.
