import 'package:flutter_test/flutter_test.dart';
import 'package:webauthn_secure_storage_windows/webauthn_secure_storage_windows.dart';
import 'package:webauthn_secure_storage_windows/src/passkey_windows.dart';
import 'package:webauthn_secure_storage_windows/src/windows_credential_store.dart';
import 'package:webauthn_secure_storage_windows/src/windows_user_consent.dart';
import 'package:webauthn_secure_storage_windows/src/windows_webauthn_bindings.dart';
import 'package:webauthn_secure_storage_platform_interface/webauthn_secure_storage_platform_interface.dart';

class _FakeWindowsWebAuthnBindings implements WindowsWebAuthnBindings {
  _FakeWindowsWebAuthnBindings({
    required this.apiVersion,
    required this.availability,
  });

  final int apiVersion;
  final WindowsPlatformAuthenticatorAvailability availability;

  @override
  int getApiVersionNumber() => apiVersion;

  @override
  WindowsPlatformAuthenticatorAvailability
  getPlatformAuthenticatorAvailability() => availability;

  @override
  PublicKeyCredentialAttestationJson registerPasskey(
    PublicKeyCredentialCreationOptionsJson options,
  ) {
    return const PublicKeyCredentialAttestationJson(
      id: 'credential-id',
      rawId: 'credential-id',
      response: AuthenticatorAttestationResponseJson(
        clientDataJSON: 'client-data',
        attestationObject: 'attestation-object',
      ),
    );
  }

  @override
  PublicKeyCredentialAssertionJson authenticateWithPasskey(
    PublicKeyCredentialRequestOptionsJson options,
  ) {
    return const PublicKeyCredentialAssertionJson(
      id: 'credential-id',
      rawId: 'credential-id',
      response: AuthenticatorAssertionResponseJson(
        clientDataJSON: 'client-data',
        authenticatorData: 'auth-data',
        signature: 'signature',
      ),
    );
  }
}

void main() {
  group('BiometricStorageWindows', () {
    late BiometricStorageWindows plugin;
    late _FakeWindowsCredentialStore credentialStore;
    late _FakeWindowsUserConsentClient userConsentClient;

    setUp(() {
      credentialStore = _FakeWindowsCredentialStore();
      userConsentClient = _FakeWindowsUserConsentClient(
        availability: WindowsUserConsentAvailability.available,
        verificationResult: WindowsUserConsentVerificationResult.verified,
      );
      plugin = BiometricStorageWindows(
        credentialStore: credentialStore,
        userConsentClient: userConsentClient,
      );
      PasskeyWindows.bindingsFactory = () => _FakeWindowsWebAuthnBindings(
        apiVersion: 1,
        availability: const WindowsPlatformAuthenticatorAvailability(
          hResult: 0,
          isAvailable: true,
        ),
      );
    });

    tearDown(() {
      PasskeyWindows.bindingsFactory = FfiWindowsWebAuthnBindings.new;
    });

    test(
      'canAuthenticate maps available Windows Hello consent to success',
      () async {
        expect(await plugin.canAuthenticate(), CanAuthenticateResponse.success);
      },
    );

    test(
      'canAuthenticate succeeds when authentication is not required',
      () async {
        userConsentClient.availability =
            WindowsUserConsentAvailability.deviceNotPresent;

        expect(
          await plugin.canAuthenticate(
            options: StorageFileInitOptions(authenticationRequired: false),
          ),
          CanAuthenticateResponse.success,
        );
      },
    );

    test(
      'getPasskeyAvailability reports native WebAuthn support metadata',
      () async {
        final availability = await plugin.getPasskeyAvailability();

        expect(availability.isSupported, isTrue);
        expect(availability.isAvailable, isTrue);
        expect(availability.hasPlatformAuthenticator, isTrue);
        expect(availability.metadata['apiVersion'], 1);
        expect(availability.metadata['availabilityCallSuccessful'], isTrue);
      },
    );

    test(
      'canAuthenticate maps missing Windows Hello support to no hardware',
      () async {
        userConsentClient.availability =
            WindowsUserConsentAvailability.deviceNotPresent;

        expect(
          await plugin.canAuthenticate(),
          CanAuthenticateResponse.errorNoHardware,
        );
      },
    );

    test(
      'canAuthenticate maps policy-disabled Windows Hello to hw unavailable',
      () async {
        userConsentClient.availability =
            WindowsUserConsentAvailability.disabledByPolicy;

        expect(
          await plugin.canAuthenticate(),
          CanAuthenticateResponse.errorHwUnavailable,
        );
      },
    );

    test('registerPasskey uses the Windows bindings implementation', () async {
      final options = PublicKeyCredentialCreationOptionsJson(
        challenge: 'challenge',
        rp: PublicKeyCredentialRpEntityJson(name: 'RP'),
        user: PublicKeyCredentialUserEntityJson(
          id: 'id',
          name: 'user',
          displayName: 'User',
        ),
        pubKeyCredParams: [],
      );

      final credential = await plugin.registerPasskey(options);

      expect(credential.id, 'credential-id');
      expect(credential.response.attestationObject, 'attestation-object');
    });

    test(
      'registerPasskey maps native not allowed errors to auth exceptions',
      () async {
        PasskeyWindows.bindingsFactory = () => _ThrowingWindowsBindings(
          apiVersion: 1,
          availability: const WindowsPlatformAuthenticatorAvailability(
            hResult: 0,
            isAvailable: true,
          ),
          error: const WindowsWebAuthnException(
            hResult: -1,
            errorName: 'NotAllowedError',
            message: 'user cancelled',
          ),
        );

        final options = PublicKeyCredentialCreationOptionsJson(
          challenge: 'challenge',
          rp: const PublicKeyCredentialRpEntityJson(
            name: 'RP',
            id: 'rp.example',
          ),
          user: const PublicKeyCredentialUserEntityJson(
            id: 'aWQ',
            name: 'user',
            displayName: 'User',
          ),
          pubKeyCredParams: const [],
        );

        await expectLater(
          plugin.registerPasskey(options),
          throwsA(isA<AuthException>()),
        );
      },
    );

    test(
      'authenticateWithPasskey uses the Windows bindings implementation',
      () async {
        final options = PublicKeyCredentialRequestOptionsJson(
          challenge: 'challenge',
          rpId: 'rp.example',
        );

        final assertion = await plugin.authenticateWithPasskey(options);

        expect(assertion.id, 'credential-id');
        expect(assertion.response.signature, 'signature');
      },
    );

    test(
      'authenticateWithPasskey maps native not allowed errors to auth exceptions',
      () async {
        PasskeyWindows.bindingsFactory = () => _ThrowingWindowsBindings(
          apiVersion: 1,
          availability: const WindowsPlatformAuthenticatorAvailability(
            hResult: 0,
            isAvailable: true,
          ),
          error: const WindowsWebAuthnException(
            hResult: -1,
            errorName: 'NotAllowedError',
            message: 'user cancelled',
          ),
        );

        final options = PublicKeyCredentialRequestOptionsJson(
          challenge: 'challenge',
          rpId: 'rp.example',
        );

        await expectLater(
          plugin.authenticateWithPasskey(options),
          throwsA(isA<AuthException>()),
        );
      },
    );

    test('read/write/delete require Windows Hello when configured', () async {
      await plugin.init(
        'secret',
        options: StorageFileInitOptions(authenticationRequired: true),
      );

      await plugin.write('secret', 'value', PromptInfo.defaultValues);
      expect(await plugin.read('secret', PromptInfo.defaultValues), 'value');
      expect(await plugin.exists('secret', PromptInfo.defaultValues), isTrue);
      expect(await plugin.delete('secret', PromptInfo.defaultValues), isTrue);

      expect(userConsentClient.verificationReasons, <String>[
        'Use Windows Hello to save protected data.',
        'Use Windows Hello to access protected data.',
        'Use Windows Hello to access protected data.',
        'Use Windows Hello to delete protected data.',
      ]);
    });

    test('unauthenticated storage skips Hello prompts by default', () async {
      await plugin.init(
        'secret',
        options: StorageFileInitOptions(authenticationRequired: false),
      );

      await plugin.write('secret', 'value', PromptInfo.defaultValues);
      expect(await plugin.read('secret', PromptInfo.defaultValues), 'value');

      expect(userConsentClient.verificationReasons, isEmpty);
    });

    test(
      'forceBiometricAuthentication prompts even without enforced auth',
      () async {
        await plugin.init(
          'secret',
          options: StorageFileInitOptions(authenticationRequired: false),
        );

        await plugin.write(
          'secret',
          'value',
          PromptInfo.defaultValues,
          forceBiometricAuthentication: true,
        );
        await plugin.read(
          'secret',
          PromptInfo.defaultValues,
          forceBiometricAuthentication: true,
        );

        expect(userConsentClient.verificationReasons, <String>[
          'Use Windows Hello to save protected data.',
          'Use Windows Hello to access protected data.',
        ]);
      },
    );

    test('canceled verification maps to an auth exception', () async {
      await plugin.init(
        'secret',
        options: StorageFileInitOptions(authenticationRequired: true),
      );
      userConsentClient.verificationResult =
          WindowsUserConsentVerificationResult.canceled;

      await expectLater(
        plugin.read('secret', PromptInfo.defaultValues),
        throwsA(isA<AuthException>()),
      );
    });

    test(
      'delete clears both namespaces so deleted legacy value does not resurface',
      () async {
        await plugin.init(
          'secret',
          options: StorageFileInitOptions(authenticationRequired: false),
        );

        // Seed the legacy namespace via the credential store's write API,
        // using the prefixed key that the plugin uses internally.
        await credentialStore.write(
          '${BiometricStorageWindows.legacyNamePrefix}secret',
          'legacy-value',
        );
        // Write via the current API so both namespaces are populated.
        await plugin.write('secret', 'new-value', PromptInfo.defaultValues);

        // After delete the credential must not be retrievable from either
        // namespace – the legacy entry must not resurface.
        expect(await plugin.delete('secret', PromptInfo.defaultValues), isTrue);
        expect(await plugin.read('secret', PromptInfo.defaultValues), isNull);
        expect(
          await plugin.exists('secret', PromptInfo.defaultValues),
          isFalse,
        );
      },
    );
  });
}

class _FakeWindowsCredentialStore implements WindowsCredentialStore {
  final Map<String, String> _values = <String, String>{};

  @override
  Future<bool> delete(String storageName, String logicalName) async =>
      _values.remove(storageName) != null;

  @override
  Future<String?> read(String storageName, String logicalName) async =>
      _values[storageName];

  @override
  Future<void> write(String storageName, String content) async {
    _values[storageName] = content;
  }
}

class _FakeWindowsUserConsentClient implements WindowsUserConsentClient {
  _FakeWindowsUserConsentClient({
    required this.availability,
    required this.verificationResult,
  });

  WindowsUserConsentAvailability availability;
  WindowsUserConsentVerificationResult verificationResult;
  final List<String> verificationReasons = <String>[];

  @override
  Future<WindowsUserConsentAvailability> getAvailability() async =>
      availability;

  @override
  Future<WindowsUserConsentVerificationResult> requestVerification({
    required String reason,
  }) async {
    verificationReasons.add(reason);
    return verificationResult;
  }
}

class _ThrowingWindowsBindings extends _FakeWindowsWebAuthnBindings {
  _ThrowingWindowsBindings({
    required super.apiVersion,
    required super.availability,
    required this.error,
  });

  final WindowsWebAuthnException error;

  @override
  PublicKeyCredentialAttestationJson registerPasskey(
    PublicKeyCredentialCreationOptionsJson options,
  ) {
    throw error;
  }

  @override
  PublicKeyCredentialAssertionJson authenticateWithPasskey(
    PublicKeyCredentialRequestOptionsJson options,
  ) {
    throw error;
  }
}
