import 'dart:convert';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:webauthn_secure_storage_linux/webauthn_secure_storage_linux.dart';
import 'package:webauthn_secure_storage_platform_interface/webauthn_secure_storage_platform_interface.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('BiometricStorageLinux Passkeys', () {
    late WebauthnSecureStorageLinux plugin;
    final List<MethodCall> log = <MethodCall>[];

    setUp(() {
      plugin = WebauthnSecureStorageLinux();
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
            MethodChannelBiometricStoragePlatform.channel,
            (MethodCall methodCall) async {
              log.add(methodCall);

              switch (methodCall.method) {
                case 'getPasskeyAvailability':
                  return <String, Object?>{
                    'isAvailable': true,
                    'isSupported': true,
                    'hasPlatformAuthenticator': false,
                  };
                case 'registerPasskey':
                  return <String, Object?>{
                    'credentialId': Uint8List.fromList(<int>[1, 2, 3]),
                    'clientDataJson': Uint8List.fromList(<int>[9]),
                    'authenticatorData': Uint8List.fromList(<int>[4, 5]),
                    'attestationStatement': Uint8List.fromList(<int>[
                      0xa1,
                      0x01,
                      0x02,
                    ]),
                    'format': 'packed',
                    'transports': <String>['usb'],
                    'publicKeyAlgorithm': -7,
                    'publicKey': Uint8List.fromList(<int>[6, 7, 8]),
                  };
                case 'authenticateWithPasskey':
                  return <String, Object?>{
                    'credentialId': Uint8List.fromList(<int>[1, 2, 3]),
                    'clientDataJson': Uint8List.fromList(<int>[9]),
                    'authenticatorData': Uint8List.fromList(<int>[4, 5]),
                    'signature': Uint8List.fromList(<int>[6, 7, 8]),
                    'userHandle': Uint8List.fromList(<int>[10, 11]),
                  };
              }

              return null;
            },
          );
    });

    tearDown(() {
      log.clear();
    });

    test(
      'getPasskeyAvailability reads the native availability contract',
      () async {
        final result = await plugin.getPasskeyAvailability();

        expect(log, hasLength(1));
        expect(log.single.method, 'getPasskeyAvailability');
        expect(result.isAvailable, isTrue);
        expect(result.isSupported, isTrue);
        expect(result.hasPlatformAuthenticator, isFalse);
      },
    );

    test('registerPasskey shapes raw native data into WebAuthn JSON', () async {
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

      final result = await plugin.registerPasskey(options);

      expect(log, hasLength(1));
      expect(log.single.method, 'registerPasskey');
      expect(result.id, 'AQID');
      expect(result.rawId, 'AQID');
      expect(result.response.clientDataJSON, 'CQ');
      expect(result.response.authenticatorData, 'BAU');
      expect(result.response.publicKeyAlgorithm, -7);
      expect(result.response.publicKey, 'BgcI');
      expect(result.response.transports, <String>['usb']);
      expect(_decodeBase64Url(result.response.attestationObject), <int>[
        0xa3,
        0x63,
        0x66,
        0x6d,
        0x74,
        0x66,
        0x70,
        0x61,
        0x63,
        0x6b,
        0x65,
        0x64,
        0x67,
        0x61,
        0x74,
        0x74,
        0x53,
        0x74,
        0x6d,
        0x74,
        0xa1,
        0x01,
        0x02,
        0x68,
        0x61,
        0x75,
        0x74,
        0x68,
        0x44,
        0x61,
        0x74,
        0x61,
        0x42,
        0x04,
        0x05,
      ]);
    });

    test('authenticateWithPasskey shapes raw native assertion data', () async {
      final options = PublicKeyCredentialRequestOptionsJson(
        challenge: 'challenge',
        rpId: 'example.com',
      );

      final result = await plugin.authenticateWithPasskey(options);

      expect(log, hasLength(1));
      expect(log.single.method, 'authenticateWithPasskey');
      expect(result.id, 'AQID');
      expect(result.rawId, 'AQID');
      expect(result.response.clientDataJSON, 'CQ');
      expect(result.response.authenticatorData, 'BAU');
      expect(result.response.signature, 'BgcI');
      expect(result.response.userHandle, 'Cgs');
    });
  });
}

List<int> _decodeBase64Url(String value) {
  final normalized = switch (value.length % 4) {
    0 => value,
    2 => '$value==',
    3 => '$value=',
    _ => throw FormatException('Invalid base64url length: ${value.length}'),
  };
  return base64Url.decode(normalized);
}
