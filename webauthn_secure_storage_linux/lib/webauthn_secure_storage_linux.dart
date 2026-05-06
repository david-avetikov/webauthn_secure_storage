import 'dart:convert';
import 'dart:typed_data';

import 'package:webauthn_secure_storage_platform_interface/webauthn_secure_storage_platform_interface.dart';

class WebauthnSecureStorageLinux extends MethodChannelBiometricStoragePlatform {
  static void registerWith() {
    BiometricStoragePlatform.instance = WebauthnSecureStorageLinux();
  }

  @override
  Future<CanAuthenticateResponse> canAuthenticate({
    StorageFileInitOptions? options,
  }) async {
    final response = await MethodChannelBiometricStoragePlatform.channel
        .invokeMethod<String>('canAuthenticate', <String, dynamic>{
          'options': options?.toJson() ?? StorageFileInitOptions().toJson(),
        });
    return mapCanAuthenticateResponse(response);
  }

  @override
  Map<String, dynamic> buildPromptInfoArguments(PromptInfo promptInfo) =>
      <String, dynamic>{};

  @override
  Future<PasskeyAvailability> getPasskeyAvailability() async {
    final Map<String, dynamic>? result = await transformErrors(
      MethodChannelBiometricStoragePlatform.channel
          .invokeMapMethod<String, dynamic>('getPasskeyAvailability'),
    );

    if (result == null) {
      return const PasskeyAvailability.unsupported();
    }

    return PasskeyAvailability.fromJson(result);
  }

  @override
  Future<PublicKeyCredentialAttestationJson> registerPasskey(
    PublicKeyCredentialCreationOptionsJson options,
  ) async {
    final clientDataJson = _buildClientDataJson(
      type: 'webauthn.create',
      challenge: options.challenge,
      origin: 'https://${options.rp.id ?? options.rp.name}',
    );
    final Map<String, dynamic>? result = await transformErrors(
      MethodChannelBiometricStoragePlatform.channel
          .invokeMapMethod<String, dynamic>(
            'registerPasskey',
            <String, dynamic>{
              'options': options.toJson(),
              'clientDataJson': clientDataJson,
            },
          ),
    );

    if (result == null) {
      throw AuthException(
        AuthExceptionCode.unknown,
        'registerPasskey returned null.',
      );
    }

    final credentialId = _encodeBase64Url(_asBytes(result['credentialId']));
    final clientDataJsonBytes =
        _asNullableBytes(result['clientDataJson']) ?? clientDataJson;
    final clientDataJsonBase64 = _encodeBase64Url(clientDataJsonBytes);
    final authenticatorDataBytes = _asBytes(result['authenticatorData']);
    final attestationStatementBytes = _asBytes(result['attestationStatement']);
    final attestationObject = _encodeBase64Url(
      _buildAttestationObject(
        format: (result['format'] as String?) ?? 'packed',
        authenticatorData: authenticatorDataBytes,
        attestationStatement: attestationStatementBytes,
      ),
    );
    final transports = (result['transports'] as List<Object?>?)
        ?.whereType<String>()
        .toList(growable: false);
    final publicKeyAlgorithm = result['publicKeyAlgorithm'] as int?;
    final publicKeyBytes = _asNullableBytes(result['publicKey']);

    return PublicKeyCredentialAttestationJson(
      id: credentialId,
      rawId: credentialId,
      type: 'public-key',
      response: AuthenticatorAttestationResponseJson(
        clientDataJSON: clientDataJsonBase64,
        attestationObject: attestationObject,
        authenticatorData: authenticatorDataBytes.isEmpty
            ? null
            : _encodeBase64Url(authenticatorDataBytes),
        transports: transports,
        publicKeyAlgorithm: publicKeyAlgorithm,
        publicKey: publicKeyBytes == null || publicKeyBytes.isEmpty
            ? null
            : _encodeBase64Url(publicKeyBytes),
      ),
      authenticatorAttachment: result['authenticatorAttachment'] as String?,
      clientExtensionResults: _mapFromNullable(
        result['clientExtensionResults'],
      ),
    );
  }

  @override
  Future<PublicKeyCredentialAssertionJson> authenticateWithPasskey(
    PublicKeyCredentialRequestOptionsJson options,
  ) async {
    final rpId = options.rpId;
    if (rpId == null || rpId.isEmpty) {
      throw AuthException(
        AuthExceptionCode.unknown,
        'Linux passkey authentication requires an rpId.',
      );
    }
    final clientDataJson = _buildClientDataJson(
      type: 'webauthn.get',
      challenge: options.challenge,
      origin: 'https://$rpId',
    );
    final Map<String, dynamic>? result = await transformErrors(
      MethodChannelBiometricStoragePlatform.channel
          .invokeMapMethod<String, dynamic>(
            'authenticateWithPasskey',
            <String, dynamic>{
              'options': options.toJson(),
              'clientDataJson': clientDataJson,
            },
          ),
    );

    if (result == null) {
      throw AuthException(
        AuthExceptionCode.unknown,
        'authenticateWithPasskey returned null.',
      );
    }

    final credentialId = _encodeBase64Url(_asBytes(result['credentialId']));
    final clientDataJsonBytes =
        _asNullableBytes(result['clientDataJson']) ?? clientDataJson;
    final clientDataJsonBase64 = _encodeBase64Url(clientDataJsonBytes);
    final authenticatorData = _encodeBase64Url(
      _asBytes(result['authenticatorData']),
    );
    final signature = _encodeBase64Url(_asBytes(result['signature']));
    final userHandleBytes = _asNullableBytes(result['userHandle']);

    return PublicKeyCredentialAssertionJson(
      id: credentialId,
      rawId: credentialId,
      type: 'public-key',
      response: AuthenticatorAssertionResponseJson(
        clientDataJSON: clientDataJsonBase64,
        authenticatorData: authenticatorData,
        signature: signature,
        userHandle: userHandleBytes == null || userHandleBytes.isEmpty
            ? null
            : _encodeBase64Url(userHandleBytes),
      ),
      authenticatorAttachment: result['authenticatorAttachment'] as String?,
      clientExtensionResults: _mapFromNullable(
        result['clientExtensionResults'],
      ),
    );
  }

  @override
  Future<bool> linuxCheckAppArmorError() async {
    await init(
      'appArmorCheck',
      options: StorageFileInitOptions(authenticationRequired: false),
    );
    try {
      await read('appArmorCheck', PromptInfo.defaultValues);
      return false;
    } on AuthException catch (e) {
      if (e.code == AuthExceptionCode.linuxAppArmorDenied) {
        return true;
      }
      rethrow;
    }
  }

  @override
  Future<void> dispose(String name, PromptInfo promptInfo) async {}
}

Uint8List _asBytes(Object? value) {
  if (value is Uint8List) {
    return value;
  }
  if (value is List<int>) {
    return Uint8List.fromList(value);
  }
  if (value is List<Object?>) {
    return Uint8List.fromList(value.whereType<int>().toList(growable: false));
  }
  throw FormatException(
    'Expected binary payload but got ${value.runtimeType}.',
  );
}

Uint8List? _asNullableBytes(Object? value) {
  if (value == null) {
    return null;
  }
  return _asBytes(value);
}

String _encodeBase64Url(Uint8List value) =>
    base64UrlEncode(value).replaceAll('=', '');

Map<String, dynamic>? _mapFromNullable(Object? value) {
  if (value == null) {
    return null;
  }
  if (value is Map<String, dynamic>) {
    return value;
  }
  if (value is Map) {
    return value.map(
      (key, dynamic mapValue) => MapEntry(key.toString(), mapValue),
    );
  }
  throw FormatException('Expected map payload but got ${value.runtimeType}.');
}

Uint8List _buildAttestationObject({
  required String format,
  required Uint8List authenticatorData,
  required Uint8List attestationStatement,
}) {
  final bytes = BytesBuilder(copy: false)
    ..add(_encodeCborMapHeader(3))
    ..add(_encodeCborText('fmt'))
    ..add(_encodeCborText(format))
    ..add(_encodeCborText('attStmt'))
    ..add(attestationStatement)
    ..add(_encodeCborText('authData'))
    ..add(_encodeCborBytes(authenticatorData));
  return bytes.toBytes();
}

Uint8List _buildClientDataJson({
  required String type,
  required String challenge,
  required String origin,
}) {
  return Uint8List.fromList(
    utf8.encode(
      jsonEncode(<String, Object?>{
        'type': type,
        'challenge': challenge,
        'origin': origin,
      }),
    ),
  );
}

Uint8List _encodeCborMapHeader(int length) => _encodeCborMajorType(5, length);

Uint8List _encodeCborText(String value) {
  final encoded = Uint8List.fromList(utf8.encode(value));
  final bytes = BytesBuilder(copy: false)
    ..add(_encodeCborMajorType(3, encoded.length))
    ..add(encoded);
  return bytes.toBytes();
}

Uint8List _encodeCborBytes(Uint8List value) {
  final bytes = BytesBuilder(copy: false)
    ..add(_encodeCborMajorType(2, value.length))
    ..add(value);
  return bytes.toBytes();
}

Uint8List _encodeCborMajorType(int majorType, int value) {
  if (value < 24) {
    return Uint8List.fromList(<int>[(majorType << 5) | value]);
  }
  if (value <= 0xff) {
    return Uint8List.fromList(<int>[(majorType << 5) | 24, value]);
  }
  if (value <= 0xffff) {
    return Uint8List.fromList(<int>[
      (majorType << 5) | 25,
      (value >> 8) & 0xff,
      value & 0xff,
    ]);
  }
  return Uint8List.fromList(<int>[
    (majorType << 5) | 26,
    (value >> 24) & 0xff,
    (value >> 16) & 0xff,
    (value >> 8) & 0xff,
    value & 0xff,
  ]);
}
