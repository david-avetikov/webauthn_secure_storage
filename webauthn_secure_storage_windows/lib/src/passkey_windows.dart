import 'package:webauthn_secure_storage_platform_interface/webauthn_secure_storage_platform_interface.dart';

import 'windows_webauthn_bindings.dart';

class PasskeyWindows {
  static WindowsWebAuthnBindings Function() bindingsFactory =
      FfiWindowsWebAuthnBindings.new;

  static WindowsWebAuthnBindings? _tryCreateBindings() {
    try {
      return bindingsFactory();
    } on Object {
      return null;
    }
  }

  static Future<CanAuthenticateResponse> getCanAuthenticateResponse() async {
    final bindings = _tryCreateBindings();
    if (bindings == null) {
      return CanAuthenticateResponse.errorNoHardware;
    }

    final apiVersion = bindings.getApiVersionNumber();
    if (apiVersion < 1) {
      return CanAuthenticateResponse.errorNoHardware;
    }

    final availability = bindings.getPlatformAuthenticatorAvailability();
    if (!availability.isCallSuccessful) {
      return CanAuthenticateResponse.errorHwUnavailable;
    }

    return availability.isAvailable
        ? CanAuthenticateResponse.success
        : CanAuthenticateResponse.errorNoHardware;
  }

  static Future<PasskeyAvailability> getAvailability() async {
    final bindings = _tryCreateBindings();
    if (bindings == null) {
      return const PasskeyAvailability.unsupported();
    }

    final apiVersion = bindings.getApiVersionNumber();
    if (apiVersion < 1) {
      return const PasskeyAvailability.unsupported();
    }

    final availability = bindings.getPlatformAuthenticatorAvailability();
    final hasPlatformAuthenticator =
        availability.isCallSuccessful && availability.isAvailable;

    return PasskeyAvailability(
      isSupported: true,
      isAvailable: hasPlatformAuthenticator,
      hasPlatformAuthenticator: hasPlatformAuthenticator,
      hasDiscoverableCredentials: hasPlatformAuthenticator,
      metadata: <String, dynamic>{
        'apiVersion': apiVersion,
        'availabilityHResult': availability.hResult,
        'availabilityCallSuccessful': availability.isCallSuccessful,
      },
    );
  }

  static Future<PublicKeyCredentialAttestationJson> registerPasskey(
    PublicKeyCredentialCreationOptionsJson options,
  ) async {
    final bindings = _tryCreateBindings();
    if (bindings == null || bindings.getApiVersionNumber() < 1) {
      throw UnsupportedError('Passkeys are not supported on Windows yet.');
    }

    try {
      return bindings.registerPasskey(options);
    } on WindowsWebAuthnException catch (error) {
      return _throwMappedException(error);
    }
  }

  static Future<PublicKeyCredentialAssertionJson> authenticateWithPasskey(
    PublicKeyCredentialRequestOptionsJson options,
  ) async {
    final bindings = _tryCreateBindings();
    if (bindings == null || bindings.getApiVersionNumber() < 1) {
      throw UnsupportedError('Passkeys are not supported on Windows yet.');
    }

    try {
      return bindings.authenticateWithPasskey(options);
    } on WindowsWebAuthnException catch (error) {
      return _throwMappedException(error);
    }
  }

  static Never _throwMappedException(WindowsWebAuthnException error) {
    switch (error.errorName) {
      case 'NotAllowedError':
        throw AuthException(AuthExceptionCode.userCanceled, error.message);
      case 'InvalidStateError':
      case 'ConstraintError':
        throw BiometricStorageException(error.message);
      case 'NotSupportedError':
        throw UnsupportedError(error.message);
      default:
        throw BiometricStorageException(error.message);
    }
  }
}
