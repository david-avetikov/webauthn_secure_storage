# WebAuthn & Secure Storage

[![Pub](https://img.shields.io/pub/v/webauthn_secure_storage?color=green)](https://pub.dev/packages/webauthn_secure_storage/)
[![License: MIT](https://img.shields.io/badge/license-MIT-purple.svg)](https://opensource.org/licenses/MIT)

A robust Flutter plugin providing cross-platform encrypted secure storage and standards-based WebAuthn/Passkey capabilities.

This package combines two essential security concepts into one seamless API:

1. **Biometric-gated secure storage**: Securely store small secrets (like authentication tokens or encryption keys) backed by hardware encryption and gated by platform biometrics (Face ID, Touch ID, Android Keystore).
2. **Passkeys / WebAuthn**: Full support for server-driven Passkey registration and authentication flows, matching W3C standards using native platform APIs.

## Features

- **Store Secrets Securely**: Use hardware-backed encryption (Apple Keychain, Android Keystore, Windows Credential Manager, Linux Secret Service).
- **Biometric Authentication**: Optionally require user verification (Fingerprint, Face ID) before reading or writing data.
- **Passkeys Support**: Native implementation of Passkey flows across Android, iOS, macOS, Windows, Linux, and Web.
- **WebAuthn PRF**: Leverage WebAuthn PRF on the web to securely store secrets when traditional secure storage isn't enough.
- **Granular Capability Checks**: Distinguish between whether a feature is supported on the hardware vs available right now (e.g. clamshell mode on macOS).
- **Desktop Native Integrations**: Uses Windows Hello / `webauthn.dll` on Windows and `libsecret` + `fprintd` + `libfido2` on Linux instead of a faux cross-platform shim.

## Supported Platforms

| Platform | Secure Storage | Biometric Gate | Passkeys / WebAuthn |
| --- | --- | --- | --- |
| **Android** | ✅ `KeyStore` | ✅ | ✅ |
| **iOS** | ✅ `KeyChain` | ✅ | ✅ |
| **macOS** | ✅ `KeyChain` | ✅ | ✅ |
| **Windows** | ✅ `Credential Manager` | ✅ `Windows Hello` | ✅ `Windows Hello / WebAuthn` |
| **Linux** | ✅ `libsecret` | ✅ `fprintd`* | ✅ `libfido2`* |
| **Web** | ✅ `WebAuthn PRF` | ✅ | ✅ |

\* Linux biometric-gated storage requires `fprintd`, an enrolled fingerprint, and compatible hardware. Linux passkeys require `libfido2` plus a supported authenticator.

---

## Getting Started

Add the dependency to your `pubspec.yaml`:

```yaml
dependencies:
  webauthn_secure_storage: ^latest_version
```

## Platform Setup

### Android

1. Ensure your `minSdkVersion` is at least `23` in `android/app/build.gradle`.
2. Your `MainActivity` must extend `FlutterFragmentActivity` instead of `FlutterActivity`.

```kotlin
// android/app/src/main/kotlin/.../MainActivity.kt
import io.flutter.embedding.android.FlutterFragmentActivity

class MainActivity: FlutterFragmentActivity() {
}
```

1. Use an AppCompat-based launch theme. In `android/app/src/main/res/values/styles.xml`:

```xml
<style name="LaunchTheme" parent="Theme.AppCompat.NoActionBar">
    <!-- your theme config -->
</style>
```

### iOS & macOS

1. Add the Face ID usage description to your `Info.plist` (for both `ios` and `macos` folders if applicable):

```xml
<key>NSFaceIDUsageDescription</key>
<string>Use Face ID / Touch ID to securely authenticate and access secrets.</string>
```

1. For **macOS Sandboxed apps**, ensure you add the Keychain access group to your `.entitlements` files (both Debug and Release):

```xml
<key>com.apple.security.app-sandbox</key>
<true/>
<key>keychain-access-groups</key>
<array>
  <string>$(AppIdentifierPrefix)$(PRODUCT_BUNDLE_IDENTIFIER)</string>
</array>
```

1. For Passkeys support on Apple platforms, you must configure **Associated Domains**. Add the following to your entitlements and configure your `apple-app-site-association` file on your server.

```xml
<key>com.apple.developer.associated-domains</key>
<array>
  <string>webcredentials:yourdomain.com</string>
</array>
```

### Windows & Linux

- **Windows**: No additional setup required out of the box. Secure storage uses DPAPI plus Windows Credential Manager, authenticated storage prompts Windows Hello before each protected read/write/delete/exists operation, and passkeys use the native Windows Hello / WebAuthn APIs exposed by `webauthn.dll`.
- **Linux**: Secure storage requires a Secret Service implementation such as GNOME Keyring via `libsecret`.
- **Linux biometrics**: Biometric-gated storage requires `fprintd`, an enrolled fingerprint, and a supported reader.
- **Linux passkeys**: Native passkey registration/authentication requires `libfido2` and a supported authenticator. On Debian/Ubuntu build agents this is typically `libfido2-dev`.
- **Linux packaging**: For Snap-packaged applications, you may need to connect the password-manager interface: `snap connect <your-snap-name>:password-manager-service`.

### Web

To use Passkeys and PRF-backed storage on the web, you must:

1. Serve your application from a secure context (`https://` or `localhost`).
2. Ensure your WebAuthn relying-party configuration matches your deployment origin.

---

## Usage

### Checking Capabilities

Hardware support doesn't always guarantee availability (e.g. a Mac in closed-clamshell mode has Touch ID supported, but currently unavailable). Use capability checks to gracefully adjust your UI.

```dart
import 'package:webauthn_secure_storage/webauthn_secure_storage.dart';

final storage = BiometricStorage();
final capabilities = await storage.getCapabilities();

if (capabilities.isCapabilityAvailable(SecureAccessCapability.passkeyAuthentication)) {
  // Offer Passkey login
} else if (capabilities.isCapabilityAvailable(SecureAccessCapability.biometricStorage)) {
  // Offer Biometric Unlock
}
```

You can also check current biometric availability directly:

```dart
final authState = await storage.canAuthenticate();
if (authState.canAuthenticateWithBiometrics) {
  // Safe to prompt
} else {
  // Fall back to password / pin
}
```

### Biometric Secure Storage

Storing local secrets to keep the user signed-in:

```dart
// 1. Get the storage instance
final store = await BiometricStorage().getStorageIfSupported(
  'my_secure_token',
  options: StorageFileInitOptions(
    authenticationRequired: true, // Prompt for biometrics
  ),
);

if (store == null) return;

// 2. Write data (prompts for biometrics if required)
await store.write('my-super-secret-token');

// 3. Read data (prompts for biometrics)
final token = await store.read();
print(token); // 'my-super-secret-token'
```

### WebAuthn / Passkeys

The plugin uses standard W3C WebAuthn DTOs, making it drop-in compatible with standard backends (e.g., ASP.NET Core, Next.js, FIDO2 servers).

#### Registering a Passkey

```dart
final biometricStorage = BiometricStorage();

// Your server generates the challenge and creation options
final serverOptions = PublicKeyCredentialCreationOptionsJson(
  challenge: 'base64url-encoded-challenge',
  rp: PublicKeyCredentialRpEntityJson(name: 'My App', id: 'myapp.com'),
  user: PublicKeyCredentialUserEntityJson(
    id: 'user-id-123',
    name: 'user@example.com',
    displayName: 'User Example',
  ),
  pubKeyCredParams: [
    PublicKeyCredentialParametersJson(alg: -7, type: 'public-key'), // ES256
    PublicKeyCredentialParametersJson(alg: -257, type: 'public-key'), // RS256
  ],
  authenticatorSelection: AuthenticatorSelectionCriteriaJson(
    userVerification: 'required',
  ),
);

// Triggers the native Passkey registration sheet
final registration = await biometricStorage.registerPasskey(serverOptions);

// Send `registration` back to your server for verification
```

#### Authenticating with a Passkey

```dart
// Your server generates the request options
final requestOptions = PublicKeyCredentialRequestOptionsJson(
  challenge: 'base64url-encoded-challenge',
  rpId: 'myapp.com',
  userVerification: 'required',
);

// Triggers the native Passkey authentication sheet
final assertion = await biometricStorage.authenticateWithPasskey(requestOptions);

// Send `assertion` back to your server for verification
```

## Contributing

See the repository for full contribution guidelines, federated architecture details, and issue tracking.

## Acknowledgements

Thank you to the original `biometric_storage` package for the initial inspiration and many of the code concepts.
