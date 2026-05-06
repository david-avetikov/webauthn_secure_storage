import 'package:webauthn_secure_storage_platform_interface/webauthn_secure_storage_platform_interface.dart';

import 'src/passkey_windows.dart';
import 'src/windows_credential_store.dart';
import 'src/windows_user_consent.dart';

class BiometricStorageWindows extends BiometricStoragePlatform {
  static const namePrefix = 'webauthn_secure_storage.';
  static const legacyNamePrefix = 'design.codeux.authpass.';

  static WindowsCredentialStore Function() credentialStoreFactory =
      CredentialManagerWindowsCredentialStore.new;

  static WindowsUserConsentClient Function() userConsentClientFactory =
      MethodChannelWindowsUserConsentClient.new;

  BiometricStorageWindows({
    WindowsCredentialStore? credentialStore,
    WindowsUserConsentClient? userConsentClient,
  }) : _credentialStore = credentialStore ?? credentialStoreFactory(),
       _userConsentClient = userConsentClient ?? userConsentClientFactory();

  final WindowsCredentialStore _credentialStore;
  final WindowsUserConsentClient _userConsentClient;
  final Map<String, StorageFileInitOptions> _initOptionsByName =
      <String, StorageFileInitOptions>{};

  static void registerWith() {
    BiometricStoragePlatform.instance = BiometricStorageWindows();
  }

  @override
  Future<PublicKeyCredentialAttestationJson> registerPasskey(
    PublicKeyCredentialCreationOptionsJson options,
  ) async => PasskeyWindows.registerPasskey(options);

  @override
  Future<PublicKeyCredentialAssertionJson> authenticateWithPasskey(
    PublicKeyCredentialRequestOptionsJson options,
  ) async => PasskeyWindows.authenticateWithPasskey(options);

  @override
  Future<PasskeyAvailability> getPasskeyAvailability() async =>
      PasskeyWindows.getAvailability();

  String _storageName(String name, {bool legacy = false}) =>
      '${legacy ? legacyNamePrefix : namePrefix}$name';

  StorageFileInitOptions _requireInitOptions(String name) {
    final initOptions = _initOptionsByName[name];
    if (initOptions == null) {
      throw BiometricStorageException("Storage '$name' was not initialized.");
    }
    return initOptions;
  }

  Future<CanAuthenticateResponse> _userConsentCanAuthenticate({
    required bool authenticationRequired,
  }) async {
    if (!authenticationRequired) {
      return CanAuthenticateResponse.success;
    }

    final availability = await _userConsentClient.getAvailability();
    return switch (availability) {
      WindowsUserConsentAvailability.available =>
        CanAuthenticateResponse.success,
      WindowsUserConsentAvailability.deviceNotPresent =>
        CanAuthenticateResponse.errorNoHardware,
      WindowsUserConsentAvailability.notConfiguredForUser =>
        CanAuthenticateResponse.errorPasscodeNotSet,
      WindowsUserConsentAvailability.disabledByPolicy ||
      WindowsUserConsentAvailability.deviceBusy ||
      WindowsUserConsentAvailability.unknown =>
        CanAuthenticateResponse.errorHwUnavailable,
    };
  }

  Future<void> _ensureUserConsent(
    String name,
    _WindowsProtectedAction action, {
    bool forceBiometricAuthentication = false,
  }) async {
    final initOptions = _requireInitOptions(name);
    if (!initOptions.authenticationRequired && !forceBiometricAuthentication) {
      return;
    }

    final result = await _userConsentClient.requestVerification(
      reason: action.reason,
    );
    switch (result) {
      case WindowsUserConsentVerificationResult.verified:
        return;
      case WindowsUserConsentVerificationResult.canceled:
        throw AuthException(
          AuthExceptionCode.userCanceled,
          'Windows Hello verification was canceled.',
        );
      case WindowsUserConsentVerificationResult.retriesExhausted:
        throw AuthException(
          AuthExceptionCode.timeout,
          'Windows Hello verification was canceled after too many failed attempts.',
        );
      case WindowsUserConsentVerificationResult.deviceNotPresent:
        throw BiometricStorageException(
          'Windows Hello is not available on this device.',
        );
      case WindowsUserConsentVerificationResult.notConfiguredForUser:
        throw BiometricStorageException(
          'Windows Hello is not configured for this user.',
        );
      case WindowsUserConsentVerificationResult.disabledByPolicy:
        throw BiometricStorageException(
          'Windows Hello verification is disabled by policy.',
        );
      case WindowsUserConsentVerificationResult.deviceBusy ||
          WindowsUserConsentVerificationResult.unknown:
        throw BiometricStorageException(
          'Windows Hello is currently unavailable.',
        );
    }
  }

  Future<String?> _readCurrentOrLegacy(String name) async {
    final currentValue = await _credentialStore.read(_storageName(name), name);
    if (currentValue != null) {
      return currentValue;
    }
    return _credentialStore.read(_storageName(name, legacy: true), name);
  }

  @override
  Future<CanAuthenticateResponse> canAuthenticate({
    StorageFileInitOptions? options,
  }) async => _userConsentCanAuthenticate(
    authenticationRequired:
        (options ?? StorageFileInitOptions()).authenticationRequired,
  );

  @override
  Future<bool?> init(
    String name, {
    StorageFileInitOptions? options,
    bool forceInit = false,
  }) async {
    if (_initOptionsByName.containsKey(name) && !forceInit) {
      return false;
    }
    _initOptionsByName[name] = options ?? StorageFileInitOptions();
    return true;
  }

  @override
  Future<bool> linuxCheckAppArmorError() async => false;

  @override
  Future<bool?> delete(String name, PromptInfo promptInfo) async {
    await _ensureUserConsent(name, _WindowsProtectedAction.delete);
    // Both namespaces must always be attempted so that a legacy credential
    // cannot resurface via _readCurrentOrLegacy after the new-namespace entry
    // has been deleted.
    final deletedNew =
        await _credentialStore.delete(_storageName(name), name);
    final deletedLegacy =
        await _credentialStore.delete(_storageName(name, legacy: true), name);
    return deletedNew || deletedLegacy;
  }

  @override
  Future<String?> read(
    String name,
    PromptInfo promptInfo, {
    bool forceBiometricAuthentication = false,
  }) async {
    await _ensureUserConsent(
      name,
      _WindowsProtectedAction.read,
      forceBiometricAuthentication: forceBiometricAuthentication,
    );
    return _readCurrentOrLegacy(name);
  }

  @override
  Future<bool> exists(String name, PromptInfo promptInfo) async {
    await _ensureUserConsent(name, _WindowsProtectedAction.read);
    return await _readCurrentOrLegacy(name) != null;
  }

  @override
  Future<void> write(
    String name,
    String content,
    PromptInfo promptInfo, {
    bool forceBiometricAuthentication = false,
  }) async {
    await _ensureUserConsent(
      name,
      _WindowsProtectedAction.write,
      forceBiometricAuthentication: forceBiometricAuthentication,
    );
    await _credentialStore.write(_storageName(name), content);
  }

  @override
  Future<void> dispose(String name, PromptInfo promptInfo) async {
    _initOptionsByName.remove(name);
  }
}

enum _WindowsProtectedAction {
  read('Use Windows Hello to access protected data.'),
  write('Use Windows Hello to save protected data.'),
  delete('Use Windows Hello to delete protected data.');

  const _WindowsProtectedAction(this.reason);

  final String reason;
}
