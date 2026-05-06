import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:webauthn_secure_storage_platform_interface/webauthn_secure_storage_platform_interface.dart';

const _webAuthnApiVersion1 = 1;
const _webAuthnApiVersion3 = 3;
const _webAuthnApiVersion4 = 4;
const _webAuthnApiVersion6 = 6;
const _webAuthnApiVersion7 = 7;
const _webAuthnApiVersion8 = 8;
const _webAuthnApiVersion9 = 9;

const _webAuthnRpEntityInformationCurrentVersion = 1;
const _webAuthnUserEntityInformationCurrentVersion = 1;
const _webAuthnClientDataCurrentVersion = 1;
const _webAuthnCoseCredentialParameterCurrentVersion = 1;
const _webAuthnCredentialExCurrentVersion = 1;

const _webAuthnAuthenticatorAttachmentAny = 0;
const _webAuthnAuthenticatorAttachmentPlatform = 1;
const _webAuthnAuthenticatorAttachmentCrossPlatform = 2;

const _webAuthnUserVerificationRequirementRequired = 1;
const _webAuthnUserVerificationRequirementPreferred = 2;
const _webAuthnUserVerificationRequirementDiscouraged = 3;

const _webAuthnAttestationConveyancePreferenceAny = 0;
const _webAuthnAttestationConveyancePreferenceNone = 1;
const _webAuthnAttestationConveyancePreferenceIndirect = 2;
const _webAuthnAttestationConveyancePreferenceDirect = 3;

const _webAuthnEnterpriseAttestationNone = 0;
const _webAuthnEnterpriseAttestationPlatformManaged = 2;
const _webAuthnLargeBlobSupportNone = 0;

const _webAuthnCtapTransportUsb = 0x00000001;
const _webAuthnCtapTransportNfc = 0x00000002;
const _webAuthnCtapTransportBle = 0x00000004;
const _webAuthnCtapTransportInternal = 0x00000010;
const _webAuthnCtapTransportHybrid = 0x00000020;
const _webAuthnCtapTransportSmartCard = 0x00000040;
const _webAuthnCtapTransportMask = 0x0000007F;

const _publicKeyCredentialType = 'public-key';
const _sha256Algorithm = 'SHA-256';

abstract interface class WindowsWebAuthnBindings {
  int getApiVersionNumber();

  WindowsPlatformAuthenticatorAvailability
  getPlatformAuthenticatorAvailability();

  PublicKeyCredentialAttestationJson registerPasskey(
    PublicKeyCredentialCreationOptionsJson options,
  );

  PublicKeyCredentialAssertionJson authenticateWithPasskey(
    PublicKeyCredentialRequestOptionsJson options,
  );
}

class WindowsPlatformAuthenticatorAvailability {
  const WindowsPlatformAuthenticatorAvailability({
    required this.hResult,
    required this.isAvailable,
  });

  final int hResult;
  final bool isAvailable;

  bool get isCallSuccessful => hResult >= 0;
}

class WindowsWebAuthnException implements Exception {
  const WindowsWebAuthnException({
    required this.hResult,
    required this.errorName,
    required this.message,
  });

  final int hResult;
  final String errorName;
  final String message;

  @override
  String toString() =>
      'WindowsWebAuthnException(hResult: $hResult, errorName: $errorName, message: $message)';
}

final class _Guid extends Struct {
  @Uint32()
  external int data1;

  @Uint16()
  external int data2;

  @Uint16()
  external int data3;

  @Array(8)
  external Array<Uint8> data4;
}

final class _WebAuthNRpEntityInformation extends Struct {
  @Uint32()
  external int dwVersion;

  external Pointer<Utf16> pwszId;

  external Pointer<Utf16> pwszName;

  external Pointer<Utf16> pwszIcon;
}

final class _WebAuthNUserEntityInformation extends Struct {
  @Uint32()
  external int dwVersion;

  @Uint32()
  external int cbId;

  external Pointer<Uint8> pbId;

  external Pointer<Utf16> pwszName;

  external Pointer<Utf16> pwszIcon;

  external Pointer<Utf16> pwszDisplayName;
}

final class _WebAuthNClientData extends Struct {
  @Uint32()
  external int dwVersion;

  @Uint32()
  external int cbClientDataJson;

  external Pointer<Uint8> pbClientDataJson;

  external Pointer<Utf16> pwszHashAlgId;
}

final class _WebAuthNCoseCredentialParameter extends Struct {
  @Uint32()
  external int dwVersion;

  external Pointer<Utf16> pwszCredentialType;

  @Int32()
  external int lAlg;
}

final class _WebAuthNCoseCredentialParameters extends Struct {
  @Uint32()
  external int cCredentialParameters;

  external Pointer<_WebAuthNCoseCredentialParameter> pCredentialParameters;
}

final class _WebAuthNCredential extends Struct {
  @Uint32()
  external int dwVersion;

  @Uint32()
  external int cbId;

  external Pointer<Uint8> pbId;

  external Pointer<Utf16> pwszCredentialType;
}

final class _WebAuthNCredentials extends Struct {
  @Uint32()
  external int cCredentials;

  external Pointer<_WebAuthNCredential> pCredentials;
}

final class _WebAuthNCredentialEx extends Struct {
  @Uint32()
  external int dwVersion;

  @Uint32()
  external int cbId;

  external Pointer<Uint8> pbId;

  external Pointer<Utf16> pwszCredentialType;

  @Uint32()
  external int dwTransports;
}

final class _WebAuthNCredentialList extends Struct {
  @Uint32()
  external int cCredentials;

  external Pointer<Pointer<_WebAuthNCredentialEx>> ppCredentials;
}

final class _WebAuthNExtension extends Struct {
  external Pointer<Utf16> pwszExtensionIdentifier;

  @Uint32()
  external int cbExtension;

  external Pointer<Void> pvExtension;
}

final class _WebAuthNExtensions extends Struct {
  @Uint32()
  external int cExtensions;

  external Pointer<_WebAuthNExtension> pExtensions;
}

final class _WebAuthNAuthenticatorMakeCredentialOptions extends Struct {
  @Uint32()
  external int dwVersion;

  @Uint32()
  external int dwTimeoutMilliseconds;

  external _WebAuthNCredentials credentialList;

  external _WebAuthNExtensions extensions;

  @Uint32()
  external int dwAuthenticatorAttachment;

  @Int32()
  external int bRequireResidentKey;

  @Uint32()
  external int dwUserVerificationRequirement;

  @Uint32()
  external int dwAttestationConveyancePreference;

  @Uint32()
  external int dwFlags;

  external Pointer<_Guid> pCancellationId;

  external Pointer<_WebAuthNCredentialList> pExcludeCredentialList;

  @Uint32()
  external int dwEnterpriseAttestation;

  @Uint32()
  external int dwLargeBlobSupport;

  @Int32()
  external int bPreferResidentKey;

  @Int32()
  external int bBrowserInPrivateMode;

  @Int32()
  external int bEnablePrf;

  external Pointer<Void> pLinkedDevice;

  @Uint32()
  external int cbJsonExt;

  external Pointer<Uint8> pbJsonExt;

  external Pointer<Void> pPrfGlobalEval;

  @Uint32()
  external int cCredentialHints;

  external Pointer<Pointer<Utf16>> ppwszCredentialHints;

  @Int32()
  external int bThirdPartyPayment;

  external Pointer<Utf16> pwszRemoteWebOrigin;

  @Uint32()
  external int cbPublicKeyCredentialCreationOptionsJson;

  external Pointer<Uint8> pbPublicKeyCredentialCreationOptionsJson;

  @Uint32()
  external int cbAuthenticatorId;

  external Pointer<Uint8> pbAuthenticatorId;
}

final class _WebAuthNAuthenticatorGetAssertionOptions extends Struct {
  @Uint32()
  external int dwVersion;

  @Uint32()
  external int dwTimeoutMilliseconds;

  external _WebAuthNCredentials credentialList;

  external _WebAuthNExtensions extensions;

  @Uint32()
  external int dwAuthenticatorAttachment;

  @Uint32()
  external int dwUserVerificationRequirement;

  @Uint32()
  external int dwFlags;

  external Pointer<Utf16> pwszU2fAppId;

  external Pointer<Int32> pbU2fAppId;

  external Pointer<_Guid> pCancellationId;

  external Pointer<_WebAuthNCredentialList> pAllowCredentialList;

  @Uint32()
  external int dwCredLargeBlobOperation;

  @Uint32()
  external int cbCredLargeBlob;

  external Pointer<Uint8> pbCredLargeBlob;

  external Pointer<Void> pHmacSecretSaltValues;

  @Int32()
  external int bBrowserInPrivateMode;

  external Pointer<Void> pLinkedDevice;

  @Int32()
  external int bAutoFill;

  @Uint32()
  external int cbJsonExt;

  external Pointer<Uint8> pbJsonExt;

  @Uint32()
  external int cCredentialHints;

  external Pointer<Pointer<Utf16>> ppwszCredentialHints;

  external Pointer<Utf16> pwszRemoteWebOrigin;

  @Uint32()
  external int cbPublicKeyCredentialRequestOptionsJson;

  external Pointer<Uint8> pbPublicKeyCredentialRequestOptionsJson;

  @Uint32()
  external int cbAuthenticatorId;

  external Pointer<Uint8> pbAuthenticatorId;
}

final class _WebAuthNCredentialAttestation extends Struct {
  @Uint32()
  external int dwVersion;

  external Pointer<Utf16> pwszFormatType;

  @Uint32()
  external int cbAuthenticatorData;

  external Pointer<Uint8> pbAuthenticatorData;

  @Uint32()
  external int cbAttestation;

  external Pointer<Uint8> pbAttestation;

  @Uint32()
  external int dwAttestationDecodeType;

  external Pointer<Void> pvAttestationDecode;

  @Uint32()
  external int cbAttestationObject;

  external Pointer<Uint8> pbAttestationObject;

  @Uint32()
  external int cbCredentialId;

  external Pointer<Uint8> pbCredentialId;

  external _WebAuthNExtensions extensions;

  @Uint32()
  external int dwUsedTransport;

  @Int32()
  external int bEpAtt;

  @Int32()
  external int bLargeBlobSupported;

  @Int32()
  external int bResidentKey;

  @Int32()
  external int bPrfEnabled;

  @Uint32()
  external int cbUnsignedExtensionOutputs;

  external Pointer<Uint8> pbUnsignedExtensionOutputs;

  external Pointer<Void> pHmacSecret;

  @Int32()
  external int bThirdPartyPayment;

  @Uint32()
  external int dwTransports;

  @Uint32()
  external int cbClientDataJson;

  external Pointer<Uint8> pbClientDataJson;

  @Uint32()
  external int cbRegistrationResponseJson;

  external Pointer<Uint8> pbRegistrationResponseJson;
}

final class _WebAuthNAssertion extends Struct {
  @Uint32()
  external int dwVersion;

  @Uint32()
  external int cbAuthenticatorData;

  external Pointer<Uint8> pbAuthenticatorData;

  @Uint32()
  external int cbSignature;

  external Pointer<Uint8> pbSignature;

  external _WebAuthNCredential credential;

  @Uint32()
  external int cbUserId;

  external Pointer<Uint8> pbUserId;

  external _WebAuthNExtensions extensions;

  @Uint32()
  external int cbCredLargeBlob;

  external Pointer<Uint8> pbCredLargeBlob;

  @Uint32()
  external int dwCredLargeBlobStatus;

  external Pointer<Void> pHmacSecret;

  @Uint32()
  external int dwUsedTransport;

  @Uint32()
  external int cbUnsignedExtensionOutputs;

  external Pointer<Uint8> pbUnsignedExtensionOutputs;

  @Uint32()
  external int cbClientDataJson;

  external Pointer<Uint8> pbClientDataJson;

  @Uint32()
  external int cbAuthenticationResponseJson;

  external Pointer<Uint8> pbAuthenticationResponseJson;
}

class FfiWindowsWebAuthnBindings implements WindowsWebAuthnBindings {
  FfiWindowsWebAuthnBindings({
    DynamicLibrary? library,
    DynamicLibrary? user32Library,
  }) : _library = library ?? DynamicLibrary.open('webauthn.dll'),
       _user32Library = user32Library ?? DynamicLibrary.open('User32.dll');

  final DynamicLibrary _library;
  final DynamicLibrary _user32Library;

  late final int Function() _getApiVersionNumber = _library
      .lookupFunction<Uint32 Function(), int Function()>(
        'WebAuthNGetApiVersionNumber',
      );

  late final int Function(Pointer<Int32>)
  _isUserVerifyingPlatformAuthenticatorAvailable = _library
      .lookupFunction<
        Int32 Function(Pointer<Int32>),
        int Function(Pointer<Int32>)
      >('WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable');

  late final int Function(
    int,
    Pointer<_WebAuthNRpEntityInformation>,
    Pointer<_WebAuthNUserEntityInformation>,
    Pointer<_WebAuthNCoseCredentialParameters>,
    Pointer<_WebAuthNClientData>,
    Pointer<_WebAuthNAuthenticatorMakeCredentialOptions>,
    Pointer<Pointer<_WebAuthNCredentialAttestation>>,
  )
  _authenticatorMakeCredential = _library
      .lookupFunction<
        Int32 Function(
          IntPtr,
          Pointer<_WebAuthNRpEntityInformation>,
          Pointer<_WebAuthNUserEntityInformation>,
          Pointer<_WebAuthNCoseCredentialParameters>,
          Pointer<_WebAuthNClientData>,
          Pointer<_WebAuthNAuthenticatorMakeCredentialOptions>,
          Pointer<Pointer<_WebAuthNCredentialAttestation>>,
        ),
        int Function(
          int,
          Pointer<_WebAuthNRpEntityInformation>,
          Pointer<_WebAuthNUserEntityInformation>,
          Pointer<_WebAuthNCoseCredentialParameters>,
          Pointer<_WebAuthNClientData>,
          Pointer<_WebAuthNAuthenticatorMakeCredentialOptions>,
          Pointer<Pointer<_WebAuthNCredentialAttestation>>,
        )
      >('WebAuthNAuthenticatorMakeCredential');

  late final int Function(
    int,
    Pointer<Utf16>,
    Pointer<_WebAuthNClientData>,
    Pointer<_WebAuthNAuthenticatorGetAssertionOptions>,
    Pointer<Pointer<_WebAuthNAssertion>>,
  )
  _authenticatorGetAssertion = _library
      .lookupFunction<
        Int32 Function(
          IntPtr,
          Pointer<Utf16>,
          Pointer<_WebAuthNClientData>,
          Pointer<_WebAuthNAuthenticatorGetAssertionOptions>,
          Pointer<Pointer<_WebAuthNAssertion>>,
        ),
        int Function(
          int,
          Pointer<Utf16>,
          Pointer<_WebAuthNClientData>,
          Pointer<_WebAuthNAuthenticatorGetAssertionOptions>,
          Pointer<Pointer<_WebAuthNAssertion>>,
        )
      >('WebAuthNAuthenticatorGetAssertion');

  late final Pointer<Utf16> Function(int) _getErrorName = _library
      .lookupFunction<
        Pointer<Utf16> Function(Int32),
        Pointer<Utf16> Function(int)
      >('WebAuthNGetErrorName');

  late final void Function(Pointer<_WebAuthNCredentialAttestation>)
  _freeCredentialAttestation = _library
      .lookupFunction<
        Void Function(Pointer<_WebAuthNCredentialAttestation>),
        void Function(Pointer<_WebAuthNCredentialAttestation>)
      >('WebAuthNFreeCredentialAttestation');

  late final void Function(Pointer<_WebAuthNAssertion>) _freeAssertion =
      _library.lookupFunction<
        Void Function(Pointer<_WebAuthNAssertion>),
        void Function(Pointer<_WebAuthNAssertion>)
      >('WebAuthNFreeAssertion');

  late final int Function() _getForegroundWindow = _user32Library
      .lookupFunction<IntPtr Function(), int Function()>('GetForegroundWindow');

  late final int Function() _getActiveWindow = _user32Library
      .lookupFunction<IntPtr Function(), int Function()>('GetActiveWindow');

  @override
  int getApiVersionNumber() => _getApiVersionNumber();

  @override
  WindowsPlatformAuthenticatorAvailability
  getPlatformAuthenticatorAvailability() {
    final availabilityPointer = calloc<Int32>();
    try {
      final hResult = _isUserVerifyingPlatformAuthenticatorAvailable(
        availabilityPointer,
      );
      return WindowsPlatformAuthenticatorAvailability(
        hResult: hResult,
        isAvailable: availabilityPointer.value != 0,
      );
    } finally {
      calloc.free(availabilityPointer);
    }
  }

  @override
  PublicKeyCredentialAttestationJson registerPasskey(
    PublicKeyCredentialCreationOptionsJson options,
  ) {
    final rpId = options.rp.id;
    if (rpId == null || !_isValidRpId(rpId)) {
      throw const FormatException(
        'Windows passkey registration requires a valid rp.id.',
      );
    }

    final apiVersion = getApiVersionNumber();
    if (apiVersion < _webAuthnApiVersion1) {
      throw UnsupportedError(
        'Windows WebAuthn APIs are unavailable on this system.',
      );
    }

    return using((Arena arena) {
      final hWnd = _resolveWindowHandle();
      if (hWnd == 0) {
        throw const WindowsWebAuthnException(
          hResult: -1,
          errorName: 'UnknownError',
          message: 'No active Windows window handle is available.',
        );
      }

      final rpIdPointer = rpId.toNativeUtf16(allocator: arena);
      final rpNamePointer = options.rp.name.toNativeUtf16(allocator: arena);
      final rpIconPointer =
          _nullableUtf16(options.rp.icon, allocator: arena) ?? nullptr;
      final userIdBytes = _decodeBase64Url(options.user.id);
      final userIdPointer = _copyBytes(userIdBytes, arena);
      final userNamePointer = options.user.name.toNativeUtf16(allocator: arena);
      final userIconPointer =
          _nullableUtf16(options.user.icon, allocator: arena) ?? nullptr;
      final userDisplayNamePointer = options.user.displayName.toNativeUtf16(
        allocator: arena,
      );
      final clientDataJsonBytes = Uint8List.fromList(
        utf8.encode(
          jsonEncode(<String, Object?>{
            'type': 'webauthn.create',
            'challenge': options.challenge,
            'origin': 'https://$rpId',
          }),
        ),
      );
      final clientDataJsonPointer = _copyBytes(clientDataJsonBytes, arena);
      final hashAlgorithmPointer = _sha256Algorithm.toNativeUtf16(
        allocator: arena,
      );

      final rpInfo = arena<_WebAuthNRpEntityInformation>()
        ..ref.dwVersion = _webAuthnRpEntityInformationCurrentVersion
        ..ref.pwszId = rpIdPointer
        ..ref.pwszName = rpNamePointer
        ..ref.pwszIcon = rpIconPointer;

      final userInfo = arena<_WebAuthNUserEntityInformation>()
        ..ref.dwVersion = _webAuthnUserEntityInformationCurrentVersion
        ..ref.cbId = userIdBytes.length
        ..ref.pbId = userIdPointer
        ..ref.pwszName = userNamePointer
        ..ref.pwszIcon = userIconPointer
        ..ref.pwszDisplayName = userDisplayNamePointer;

      final clientData = arena<_WebAuthNClientData>()
        ..ref.dwVersion = _webAuthnClientDataCurrentVersion
        ..ref.cbClientDataJson = clientDataJsonBytes.length
        ..ref.pbClientDataJson = clientDataJsonPointer
        ..ref.pwszHashAlgId = hashAlgorithmPointer;

      final credentialParameters = options.pubKeyCredParams.isEmpty
          ? _defaultCredentialParameters
          : options.pubKeyCredParams;
      final credentialParametersPointer =
          arena<_WebAuthNCoseCredentialParameter>(credentialParameters.length);
      final publicKeyCredentialTypePointer = _publicKeyCredentialType
          .toNativeUtf16(allocator: arena);
      for (var index = 0; index < credentialParameters.length; index++) {
        credentialParametersPointer[index]
          ..dwVersion = _webAuthnCoseCredentialParameterCurrentVersion
          ..pwszCredentialType = publicKeyCredentialTypePointer
          ..lAlg = credentialParameters[index].alg;
      }

      final credentialParametersList =
          arena<_WebAuthNCoseCredentialParameters>()
            ..ref.cCredentialParameters = credentialParameters.length
            ..ref.pCredentialParameters = credentialParametersPointer;

      final excludeCredentialList = _buildCredentialList(
        arena: arena,
        descriptors: options.excludeCredentials,
        credentialTypePointer: publicKeyCredentialTypePointer,
      );

      final makeCredentialOptions =
          arena<_WebAuthNAuthenticatorMakeCredentialOptions>()
            ..ref.dwVersion = _makeCredentialOptionsVersionForApi(apiVersion)
            ..ref.dwTimeoutMilliseconds = options.timeout ?? 60000
            ..ref.dwAuthenticatorAttachment = _mapAuthenticatorAttachment(
              options.authenticatorSelection?.authenticatorAttachment,
            )
            ..ref.bRequireResidentKey = _shouldRequireResidentKey(
              options.authenticatorSelection,
            )
            ..ref.dwUserVerificationRequirement =
                _mapUserVerificationRequirement(
                  options.authenticatorSelection?.userVerification,
                )
            ..ref.dwAttestationConveyancePreference = _mapAttestationPreference(
              options.attestation,
            )
            ..ref.dwFlags = 0
            ..ref.pCancellationId = nullptr
            ..ref.pExcludeCredentialList = excludeCredentialList ?? nullptr
            ..ref.dwEnterpriseAttestation = options.attestation == 'enterprise'
                ? _webAuthnEnterpriseAttestationPlatformManaged
                : _webAuthnEnterpriseAttestationNone
            ..ref.dwLargeBlobSupport = _webAuthnLargeBlobSupportNone
            ..ref.bPreferResidentKey = _shouldPreferResidentKey(
              options.authenticatorSelection,
            )
            ..ref.bBrowserInPrivateMode = 0
            ..ref.bEnablePrf = 0
            ..ref.pLinkedDevice = nullptr
            ..ref.cbJsonExt = 0
            ..ref.pbJsonExt = nullptr
            ..ref.pPrfGlobalEval = nullptr
            ..ref.cCredentialHints = 0
            ..ref.ppwszCredentialHints = nullptr
            ..ref.bThirdPartyPayment = 0
            ..ref.pwszRemoteWebOrigin = nullptr
            ..ref.cbPublicKeyCredentialCreationOptionsJson = 0
            ..ref.pbPublicKeyCredentialCreationOptionsJson = nullptr
            ..ref.cbAuthenticatorId = 0
            ..ref.pbAuthenticatorId = nullptr;

      final attestationPointer =
          arena<Pointer<_WebAuthNCredentialAttestation>>();
      final hResult = _authenticatorMakeCredential(
        hWnd,
        rpInfo,
        userInfo,
        credentialParametersList,
        clientData,
        makeCredentialOptions,
        attestationPointer,
      );
      _throwIfFailed(hResult, 'Windows WebAuthn registration failed.');

      final attestation = attestationPointer.value;
      try {
        final response = attestation.ref;
        final credentialId = _encodeBase64Url(
          response.pbCredentialId,
          response.cbCredentialId,
        );
        final attestationObject = _encodeBase64Url(
          response.pbAttestationObject,
          response.cbAttestationObject,
        );
        final authenticatorData = _encodeBase64Url(
          response.pbAuthenticatorData,
          response.cbAuthenticatorData,
        );

        return PublicKeyCredentialAttestationJson(
          id: credentialId,
          rawId: credentialId,
          response: AuthenticatorAttestationResponseJson(
            clientDataJSON: _encodeBase64Url(
              response.cbClientDataJson > 0
                  ? response.pbClientDataJson
                  : clientDataJsonPointer,
              response.cbClientDataJson > 0
                  ? response.cbClientDataJson
                  : clientDataJsonBytes.length,
            ),
            attestationObject: attestationObject,
            authenticatorData: authenticatorData.isEmpty
                ? null
                : authenticatorData,
            transports: _transportNames(
              response.dwTransports != 0
                  ? response.dwTransports
                  : response.dwUsedTransport,
            ),
          ),
        );
      } finally {
        _freeCredentialAttestation(attestation);
      }
    });
  }

  @override
  PublicKeyCredentialAssertionJson authenticateWithPasskey(
    PublicKeyCredentialRequestOptionsJson options,
  ) {
    final rpId = options.rpId;
    if (rpId == null || !_isValidRpId(rpId)) {
      throw const FormatException(
        'Windows passkey authentication requires a valid rpId.',
      );
    }

    final apiVersion = getApiVersionNumber();
    if (apiVersion < _webAuthnApiVersion1) {
      throw UnsupportedError(
        'Windows WebAuthn APIs are unavailable on this system.',
      );
    }

    return using((Arena arena) {
      final hWnd = _resolveWindowHandle();
      if (hWnd == 0) {
        throw const WindowsWebAuthnException(
          hResult: -1,
          errorName: 'UnknownError',
          message: 'No active Windows window handle is available.',
        );
      }

      final rpIdPointer = rpId.toNativeUtf16(allocator: arena);
      final clientDataJsonBytes = Uint8List.fromList(
        utf8.encode(
          jsonEncode(<String, Object?>{
            'type': 'webauthn.get',
            'challenge': options.challenge,
            'origin': 'https://$rpId',
          }),
        ),
      );
      final clientDataJsonPointer = _copyBytes(clientDataJsonBytes, arena);
      final hashAlgorithmPointer = _sha256Algorithm.toNativeUtf16(
        allocator: arena,
      );
      final publicKeyCredentialTypePointer = _publicKeyCredentialType
          .toNativeUtf16(allocator: arena);

      final clientData = arena<_WebAuthNClientData>()
        ..ref.dwVersion = _webAuthnClientDataCurrentVersion
        ..ref.cbClientDataJson = clientDataJsonBytes.length
        ..ref.pbClientDataJson = clientDataJsonPointer
        ..ref.pwszHashAlgId = hashAlgorithmPointer;

      final allowCredentialList = _buildCredentialList(
        arena: arena,
        descriptors: options.allowCredentials,
        credentialTypePointer: publicKeyCredentialTypePointer,
      );

      final getAssertionOptions =
          arena<_WebAuthNAuthenticatorGetAssertionOptions>()
            ..ref.dwVersion = _getAssertionOptionsVersionForApi(apiVersion)
            ..ref.dwTimeoutMilliseconds = options.timeout ?? 60000
            ..ref.dwAuthenticatorAttachment =
                _webAuthnAuthenticatorAttachmentAny
            ..ref.dwUserVerificationRequirement =
                _mapUserVerificationRequirement(options.userVerification)
            ..ref.dwFlags = 0
            ..ref.pwszU2fAppId = nullptr
            ..ref.pbU2fAppId = nullptr
            ..ref.pCancellationId = nullptr
            ..ref.pAllowCredentialList = allowCredentialList ?? nullptr
            ..ref.dwCredLargeBlobOperation = 0
            ..ref.cbCredLargeBlob = 0
            ..ref.pbCredLargeBlob = nullptr
            ..ref.pHmacSecretSaltValues = nullptr
            ..ref.bBrowserInPrivateMode = 0
            ..ref.pLinkedDevice = nullptr
            ..ref.bAutoFill = 0
            ..ref.cbJsonExt = 0
            ..ref.pbJsonExt = nullptr
            ..ref.cCredentialHints = 0
            ..ref.ppwszCredentialHints = nullptr
            ..ref.pwszRemoteWebOrigin = nullptr
            ..ref.cbPublicKeyCredentialRequestOptionsJson = 0
            ..ref.pbPublicKeyCredentialRequestOptionsJson = nullptr
            ..ref.cbAuthenticatorId = 0
            ..ref.pbAuthenticatorId = nullptr;

      final assertionPointer = arena<Pointer<_WebAuthNAssertion>>();
      final hResult = _authenticatorGetAssertion(
        hWnd,
        rpIdPointer,
        clientData,
        getAssertionOptions,
        assertionPointer,
      );
      _throwIfFailed(hResult, 'Windows WebAuthn assertion failed.');

      final assertion = assertionPointer.value;
      try {
        final response = assertion.ref;
        final credentialId = _encodeBase64Url(
          response.credential.pbId,
          response.credential.cbId,
        );
        return PublicKeyCredentialAssertionJson(
          id: credentialId,
          rawId: credentialId,
          response: AuthenticatorAssertionResponseJson(
            clientDataJSON: _encodeBase64Url(
              response.cbClientDataJson > 0
                  ? response.pbClientDataJson
                  : clientDataJsonPointer,
              response.cbClientDataJson > 0
                  ? response.cbClientDataJson
                  : clientDataJsonBytes.length,
            ),
            authenticatorData: _encodeBase64Url(
              response.pbAuthenticatorData,
              response.cbAuthenticatorData,
            ),
            signature: _encodeBase64Url(
              response.pbSignature,
              response.cbSignature,
            ),
            userHandle: response.cbUserId > 0
                ? _encodeBase64Url(response.pbUserId, response.cbUserId)
                : null,
          ),
        );
      } finally {
        _freeAssertion(assertion);
      }
    });
  }

  int _resolveWindowHandle() {
    final foreground = _getForegroundWindow();
    if (foreground != 0) {
      return foreground;
    }
    return _getActiveWindow();
  }

  void _throwIfFailed(int hResult, String message) {
    if (hResult >= 0) {
      return;
    }

    final errorNamePointer = _getErrorName(hResult);
    final errorName = errorNamePointer == nullptr
        ? 'UnknownError'
        : errorNamePointer.toDartString();
    throw WindowsWebAuthnException(
      hResult: hResult,
      errorName: errorName,
      message: '$message [$errorName / $hResult]',
    );
  }
}

Pointer<Uint8> _copyBytes(Uint8List bytes, Allocator allocator) {
  if (bytes.isEmpty) {
    return nullptr;
  }
  final pointer = allocator<Uint8>(bytes.length);
  pointer.asTypedList(bytes.length).setAll(0, bytes);
  return pointer;
}

Pointer<Utf16>? _nullableUtf16(String? value, {required Allocator allocator}) {
  if (value == null || value.isEmpty) {
    return null;
  }
  return value.toNativeUtf16(allocator: allocator);
}

bool _isValidRpId(String rpId) =>
    rpId.isNotEmpty &&
    !rpId.startsWith('.') &&
    !rpId.contains('://') &&
    !rpId.contains('/');

Uint8List _decodeBase64Url(String value) {
  final normalized = value.padRight(
    value.length + ((4 - value.length % 4) % 4),
    '=',
  );
  return Uint8List.fromList(base64Url.decode(normalized));
}

String _encodeBase64Url(Pointer<Uint8> pointer, int length) {
  if (pointer == nullptr || length <= 0) {
    return '';
  }
  return base64Url.encode(pointer.asTypedList(length)).replaceAll('=', '');
}

Pointer<_WebAuthNCredentialList>? _buildCredentialList({
  required Arena arena,
  required List<PublicKeyCredentialDescriptorJson>? descriptors,
  required Pointer<Utf16> credentialTypePointer,
}) {
  final resolvedDescriptors =
      descriptors ?? const <PublicKeyCredentialDescriptorJson>[];
  if (resolvedDescriptors.isEmpty) {
    return null;
  }

  final credentialsPointer = arena<_WebAuthNCredentialEx>(
    resolvedDescriptors.length,
  );
  final credentialPointers = arena<Pointer<_WebAuthNCredentialEx>>(
    resolvedDescriptors.length,
  );

  for (var index = 0; index < resolvedDescriptors.length; index++) {
    final descriptor = resolvedDescriptors[index];
    final idBytes = _decodeBase64Url(descriptor.id);
    final idPointer = _copyBytes(idBytes, arena);
    credentialsPointer[index]
      ..dwVersion = _webAuthnCredentialExCurrentVersion
      ..cbId = idBytes.length
      ..pbId = idPointer
      ..pwszCredentialType = credentialTypePointer
      ..dwTransports = _transportMaskFromStrings(descriptor.transports);
    credentialPointers[index] = credentialsPointer + index;
  }

  final listPointer = arena<_WebAuthNCredentialList>()
    ..ref.cCredentials = resolvedDescriptors.length
    ..ref.ppCredentials = credentialPointers;
  return listPointer;
}

int _makeCredentialOptionsVersionForApi(int apiVersion) {
  if (apiVersion >= _webAuthnApiVersion9) return 9;
  if (apiVersion >= _webAuthnApiVersion8) return 8;
  if (apiVersion >= _webAuthnApiVersion7) return 7;
  if (apiVersion >= _webAuthnApiVersion6) return 6;
  if (apiVersion >= _webAuthnApiVersion4) return 5;
  if (apiVersion >= _webAuthnApiVersion3) return 4;
  return 3;
}

int _getAssertionOptionsVersionForApi(int apiVersion) {
  if (apiVersion >= _webAuthnApiVersion9) return 9;
  if (apiVersion >= _webAuthnApiVersion8) return 8;
  if (apiVersion >= _webAuthnApiVersion7) return 7;
  if (apiVersion >= _webAuthnApiVersion4) return 6;
  if (apiVersion >= _webAuthnApiVersion3) return 5;
  return 4;
}

int _mapAuthenticatorAttachment(String? value) {
  return switch (value) {
    'platform' => _webAuthnAuthenticatorAttachmentPlatform,
    'cross-platform' => _webAuthnAuthenticatorAttachmentCrossPlatform,
    _ => _webAuthnAuthenticatorAttachmentAny,
  };
}

int _mapUserVerificationRequirement(String? value) {
  return switch (value) {
    'required' => _webAuthnUserVerificationRequirementRequired,
    'discouraged' => _webAuthnUserVerificationRequirementDiscouraged,
    'preferred' => _webAuthnUserVerificationRequirementPreferred,
    _ => _webAuthnUserVerificationRequirementPreferred,
  };
}

int _mapAttestationPreference(String? value) {
  return switch (value) {
    'none' => _webAuthnAttestationConveyancePreferenceNone,
    'indirect' => _webAuthnAttestationConveyancePreferenceIndirect,
    'direct' => _webAuthnAttestationConveyancePreferenceDirect,
    'enterprise' => _webAuthnAttestationConveyancePreferenceDirect,
    _ => _webAuthnAttestationConveyancePreferenceAny,
  };
}

int _shouldRequireResidentKey(AuthenticatorSelectionCriteriaJson? selection) {
  if (selection == null) {
    return 0;
  }
  if (selection.requireResidentKey == true) {
    return 1;
  }
  return selection.residentKey == 'required' ? 1 : 0;
}

int _shouldPreferResidentKey(AuthenticatorSelectionCriteriaJson? selection) {
  if (selection == null) {
    return 0;
  }
  return selection.residentKey == 'preferred' ? 1 : 0;
}

int _transportMaskFromStrings(List<String>? transports) {
  if (transports == null || transports.isEmpty) {
    return _webAuthnCtapTransportMask;
  }

  var mask = 0;
  for (final transport in transports) {
    mask |= switch (transport) {
      'usb' => _webAuthnCtapTransportUsb,
      'nfc' => _webAuthnCtapTransportNfc,
      'ble' => _webAuthnCtapTransportBle,
      'internal' => _webAuthnCtapTransportInternal,
      'hybrid' => _webAuthnCtapTransportHybrid,
      'smart-card' => _webAuthnCtapTransportSmartCard,
      _ => 0,
    };
  }
  return mask;
}

List<String>? _transportNames(int transports) {
  if (transports == 0) {
    return null;
  }

  final values = <String>[];
  if ((transports & _webAuthnCtapTransportUsb) != 0) values.add('usb');
  if ((transports & _webAuthnCtapTransportNfc) != 0) values.add('nfc');
  if ((transports & _webAuthnCtapTransportBle) != 0) values.add('ble');
  if ((transports & _webAuthnCtapTransportInternal) != 0) {
    values.add('internal');
  }
  if ((transports & _webAuthnCtapTransportHybrid) != 0) {
    values.add('hybrid');
  }
  if ((transports & _webAuthnCtapTransportSmartCard) != 0) {
    values.add('smart-card');
  }
  return values.isEmpty ? null : values;
}

const _defaultCredentialParameters = <PublicKeyCredentialParametersJson>[
  PublicKeyCredentialParametersJson(type: _publicKeyCredentialType, alg: -7),
  PublicKeyCredentialParametersJson(type: _publicKeyCredentialType, alg: -257),
];
