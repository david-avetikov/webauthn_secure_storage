import 'package:flutter_test/flutter_test.dart';
import 'package:webauthn_secure_storage_windows/webauthn_secure_storage_windows.dart';
import 'package:webauthn_secure_storage_windows/src/passkey_windows.dart';
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
  group('BiometricStorageWindows Passkeys', () {
    late BiometricStorageWindows plugin;

    setUp(() {
      plugin = BiometricStorageWindows();
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
      'canAuthenticate maps available platform authenticator to success',
      () async {
        expect(await plugin.canAuthenticate(), CanAuthenticateResponse.success);
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
      'canAuthenticate maps missing platform authenticator to no hardware',
      () async {
        PasskeyWindows.bindingsFactory = () => _FakeWindowsWebAuthnBindings(
          apiVersion: 1,
          availability: const WindowsPlatformAuthenticatorAvailability(
            hResult: 0,
            isAvailable: false,
          ),
        );

        expect(
          await plugin.canAuthenticate(),
          CanAuthenticateResponse.errorNoHardware,
        );
      },
    );

    test(
      'canAuthenticate maps failed native availability call to hw unavailable',
      () async {
        PasskeyWindows.bindingsFactory = () => _FakeWindowsWebAuthnBindings(
          apiVersion: 1,
          availability: const WindowsPlatformAuthenticatorAvailability(
            hResult: -1,
            isAvailable: false,
          ),
        );

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
  });
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
