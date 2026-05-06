// ignore_for_file: non_constant_identifier_names

import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:webauthn_secure_storage_platform_interface/webauthn_secure_storage_platform_interface.dart';
import 'package:ffi/ffi.dart';
import 'package:logging/logging.dart';

import 'src/passkey_windows.dart';

final _logger = Logger('webauthn_secure_storage_windows');

const _credTypeGeneric = 1;
const _credPersistLocalMachine = 2;
const _errorNotFound = 1168;

final DynamicLibrary _advapi32 = DynamicLibrary.open('Advapi32.dll');
final DynamicLibrary _kernel32 = DynamicLibrary.open('Kernel32.dll');

final int Function(Pointer<Utf16>, int, int) _credDelete = _advapi32
    .lookupFunction<
      Int32 Function(Pointer<Utf16>, Uint32, Uint32),
      int Function(Pointer<Utf16>, int, int)
    >('CredDeleteW');

final int Function(Pointer<Utf16>, int, int, Pointer<Pointer<_Credential>>)
_credRead = _advapi32
    .lookupFunction<
      Int32 Function(
        Pointer<Utf16>,
        Uint32,
        Uint32,
        Pointer<Pointer<_Credential>>,
      ),
      int Function(Pointer<Utf16>, int, int, Pointer<Pointer<_Credential>>)
    >('CredReadW');

final int Function(Pointer<_Credential>, int) _credWrite = _advapi32
    .lookupFunction<
      Int32 Function(Pointer<_Credential>, Uint32),
      int Function(Pointer<_Credential>, int)
    >('CredWriteW');

final void Function(Pointer<Void>) _credFree = _advapi32
    .lookupFunction<Void Function(Pointer<Void>), void Function(Pointer<Void>)>(
      'CredFree',
    );

final int Function() _getLastError = _kernel32
    .lookupFunction<Uint32 Function(), int Function()>('GetLastError');

final class _FileTime extends Struct {
  @Uint32()
  external int dwLowDateTime;

  @Uint32()
  external int dwHighDateTime;
}

final class _Credential extends Struct {
  @Uint32()
  external int Flags;

  @Uint32()
  external int Type;

  external Pointer<Utf16> TargetName;

  external Pointer<Utf16> Comment;

  external _FileTime LastWritten;

  @Uint32()
  external int CredentialBlobSize;

  external Pointer<Uint8> CredentialBlob;

  @Uint32()
  external int Persist;

  @Uint32()
  external int AttributeCount;

  external Pointer<Void> Attributes;

  external Pointer<Utf16> TargetAlias;

  external Pointer<Utf16> UserName;
}

class BiometricStorageWindows extends BiometricStoragePlatform {
  static const namePrefix = 'webauthn_secure_storage.';
  static const legacyNamePrefix = 'design.codeux.authpass.';

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

  Future<bool> _deleteByStorageName(
    String storageName,
    String logicalName,
  ) async {
    final namePointer = storageName.toNativeUtf16(allocator: calloc);
    try {
      final result = _credDelete(namePointer, _credTypeGeneric, 0);
      if (result == 0) {
        final errorCode = _getLastError();
        if (errorCode == _errorNotFound) {
          _logger.fine('Unable to find credential of name $logicalName');
        } else {
          _logger.warning('Error deleting credential $logicalName: $errorCode');
        }
        return false;
      }
    } finally {
      calloc.free(namePointer);
    }
    return true;
  }

  Future<String?> _readByStorageName(
    String storageName,
    String logicalName,
  ) async {
    final credPointer = calloc<Pointer<_Credential>>();
    final namePointer = storageName.toNativeUtf16(allocator: calloc);
    try {
      final result = _credRead(namePointer, _credTypeGeneric, 0, credPointer);
      if (result == 0) {
        final errorCode = _getLastError();
        if (errorCode == _errorNotFound) {
          _logger.fine('Unable to find credential of name $logicalName');
        } else {
          _logger.warning('Error reading credential $logicalName: $errorCode');
        }
        return null;
      }

      final cred = credPointer.value.ref;
      if (cred.CredentialBlobSize == 0) {
        return '';
      }

      final blob = Uint8List.fromList(
        cred.CredentialBlob.asTypedList(cred.CredentialBlobSize),
      );
      final value = utf8.decode(blob);
      _credFree(credPointer.value.cast<Void>());
      return value;
    } finally {
      calloc.free(credPointer);
      calloc.free(namePointer);
    }
  }

  @override
  Future<CanAuthenticateResponse> canAuthenticate({
    StorageFileInitOptions? options,
  }) async => PasskeyWindows.getCanAuthenticateResponse();

  @override
  Future<bool?> init(
    String name, {
    StorageFileInitOptions? options,
    bool forceInit = false,
  }) async => true;

  @override
  Future<bool> linuxCheckAppArmorError() async => false;

  @override
  Future<bool?> delete(String name, PromptInfo promptInfo) async =>
      await _deleteByStorageName(_storageName(name), name) ||
      await _deleteByStorageName(_storageName(name, legacy: true), name);

  @override
  Future<String?> read(
    String name,
    PromptInfo promptInfo, {
    bool forceBiometricAuthentication = false,
  }) async {
    final currentValue = await _readByStorageName(_storageName(name), name);
    if (currentValue != null) {
      return currentValue;
    }
    return _readByStorageName(_storageName(name, legacy: true), name);
  }

  @override
  Future<bool> exists(String name, PromptInfo promptInfo) async =>
      await read(name, promptInfo) != null;

  @override
  Future<void> write(
    String name,
    String content,
    PromptInfo promptInfo, {
    bool forceBiometricAuthentication = false,
  }) async {
    final passwordBytes = Uint8List.fromList(utf8.encode(content));
    final blob = passwordBytes.isEmpty
        ? nullptr
        : calloc<Uint8>(passwordBytes.length);
    if (blob != nullptr) {
      blob.asTypedList(passwordBytes.length).setAll(0, passwordBytes);
    }
    final namePointer = _storageName(name).toNativeUtf16(allocator: calloc);
    final userNamePointer = 'flutter.webauthn_secure_storage'.toNativeUtf16(
      allocator: calloc,
    );

    final credential = calloc<_Credential>()
      ..ref.Type = _credTypeGeneric
      ..ref.TargetName = namePointer
      ..ref.Persist = _credPersistLocalMachine
      ..ref.UserName = userNamePointer
      ..ref.CredentialBlob = blob
      ..ref.CredentialBlobSize = passwordBytes.length;
    try {
      final result = _credWrite(credential, 0);
      if (result == 0) {
        throw BiometricStorageException(
          'Error writing credential $name: ${_getLastError()}',
        );
      }
    } finally {
      if (blob != nullptr) {
        calloc.free(blob);
      }
      calloc.free(credential);
      calloc.free(namePointer);
      calloc.free(userNamePointer);
    }
  }

  @override
  Future<void> dispose(String name, PromptInfo promptInfo) async {}
}
