import 'dart:typed_data';

import 'package:webauthn_secure_storage_platform_interface/webauthn_secure_storage_platform_interface.dart';

const webAuthnUnsupportedMessage =
    'webauthn_secure_storage on web requires a secure-context browser with '
    'WebAuthn PRF support and a user-verifying platform authenticator. '
    'If the browser cannot prove that capability at runtime, web support is '
    'reported as unsupported instead of falling back to weaker storage.';

const webAuthnStubRuntimeMessage =
    'webauthn_secure_storage web runtime is not linked for this compilation '
    'target. Ensure the app is built for Flutter Web (dart.library.ui_web) '
    'and not using the unsupported stub implementation.';

abstract class WebAuthnRuntime {
  Future<WebAuthnSupport> probeSupport();

  String? readRecord(String key);

  void writeRecord(String key, String value);

  void deleteRecord(String key);

  Uint8List randomBytes(int length);

  Future<Uint8List> encrypt({required Uint8List keyBytes, required Uint8List plaintext});

  Future<Uint8List> decrypt({required Uint8List keyBytes, required Uint8List ciphertext});

  Future<Uint8List> registerCredential({
    required String storageName,
    required Uint8List challenge,
    required Uint8List userId,
    required Uint8List prfSalt,
  });

  Future<PublicKeyCredentialAttestationJson> registerPasskey(PublicKeyCredentialCreationOptionsJson options);

  Future<PublicKeyCredentialAssertionJson> authenticateWithPasskey(PublicKeyCredentialRequestOptionsJson options);

  Future<Uint8List> derivePrfSecret({
    required Uint8List credentialId,
    required Uint8List prfSalt,
    required bool forceBiometricAuthentication,
  });

  String describeError(Object error);

  String? errorName(Object error);
}

class WebAuthnSupport {
  const WebAuthnSupport({
    required this.isSecureContext,
    required this.hasCredentialsApi,
    required this.hasPublicKeyCredential,
    required this.supportsPrf,
    required this.hasPlatformAuthenticator,
    this.hasConditionalUi = false,
  });

  final bool isSecureContext;
  final bool hasCredentialsApi;
  final bool hasPublicKeyCredential;
  final bool supportsPrf;
  final bool hasPlatformAuthenticator;
  final bool hasConditionalUi;

  bool get isPasskeySupported => isSecureContext && hasCredentialsApi && hasPublicKeyCredential;

  bool get isStorageSupported => isPasskeySupported && supportsPrf;
}
