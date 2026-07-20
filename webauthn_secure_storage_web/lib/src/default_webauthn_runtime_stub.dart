import 'dart:typed_data';

import 'package:webauthn_secure_storage_platform_interface/webauthn_secure_storage_platform_interface.dart';

import 'webauthn_runtime.dart';

WebAuthnRuntime createDefaultWebAuthnRuntime() => _UnsupportedWebAuthnRuntime();

class _UnsupportedWebAuthnRuntime implements WebAuthnRuntime {
  @override
  Future<WebAuthnSupport> probeSupport() async => const WebAuthnSupport(
    isSecureContext: false,
    hasCredentialsApi: false,
    hasPublicKeyCredential: false,
    supportsPrf: false,
    hasPlatformAuthenticator: false,
  );

  @override
  String? readRecord(String key) => null;

  @override
  void writeRecord(String key, String value) {}

  @override
  void deleteRecord(String key) {}

  @override
  Uint8List randomBytes(int length) => Uint8List(length);

  @override
  Future<Uint8List> encrypt({required Uint8List keyBytes, required Uint8List plaintext}) async {
    throw UnsupportedError(webAuthnStubRuntimeMessage);
  }

  @override
  Future<Uint8List> decrypt({required Uint8List keyBytes, required Uint8List ciphertext}) async {
    throw UnsupportedError(webAuthnStubRuntimeMessage);
  }

  @override
  Future<Uint8List> registerCredential({
    required String storageName,
    required Uint8List challenge,
    required Uint8List userId,
    required Uint8List prfSalt,
  }) async {
    throw UnsupportedError(webAuthnStubRuntimeMessage);
  }

  @override
  Future<PublicKeyCredentialAttestationJson> registerPasskey(PublicKeyCredentialCreationOptionsJson options) async {
    throw UnsupportedError(webAuthnStubRuntimeMessage);
  }

  @override
  Future<PublicKeyCredentialAssertionJson> authenticateWithPasskey(
    PublicKeyCredentialRequestOptionsJson options,
  ) async {
    throw UnsupportedError(webAuthnStubRuntimeMessage);
  }

  @override
  Future<Uint8List> derivePrfSecret({
    required Uint8List credentialId,
    required Uint8List prfSalt,
    required bool forceBiometricAuthentication,
  }) async {
    throw UnsupportedError(webAuthnStubRuntimeMessage);
  }

  @override
  String describeError(Object error) => error.toString();

  @override
  String? errorName(Object error) => null;
}
