// ignore_for_file: non_constant_identifier_names

import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:logging/logging.dart';
import 'package:webauthn_secure_storage_platform_interface/webauthn_secure_storage_platform_interface.dart';

final _logger = Logger('webauthn_secure_storage_windows');

abstract interface class WindowsCredentialStore {
  Future<bool> delete(String storageName, String logicalName);

  Future<String?> read(String storageName, String logicalName);

  Future<void> write(String storageName, String content);
}

class CredentialManagerWindowsCredentialStore
    implements WindowsCredentialStore {
  static const _credTypeGeneric = 1;
  static const _credPersistLocalMachine = 2;
  static const _errorNotFound = 1168;
  static final DynamicLibrary _advapi32 = DynamicLibrary.open('Advapi32.dll');
  static final DynamicLibrary _kernel32 = DynamicLibrary.open('Kernel32.dll');

  CredentialManagerWindowsCredentialStore()
    : _credDelete = _advapi32
          .lookupFunction<
            Int32 Function(Pointer<Utf16>, Uint32, Uint32),
            int Function(Pointer<Utf16>, int, int)
          >('CredDeleteW'),
      _credRead = _advapi32
          .lookupFunction<
            Int32 Function(
              Pointer<Utf16>,
              Uint32,
              Uint32,
              Pointer<Pointer<_Credential>>,
            ),
            int Function(
              Pointer<Utf16>,
              int,
              int,
              Pointer<Pointer<_Credential>>,
            )
          >('CredReadW'),
      _credWrite = _advapi32
          .lookupFunction<
            Int32 Function(Pointer<_Credential>, Uint32),
            int Function(Pointer<_Credential>, int)
          >('CredWriteW'),
      _credFree = _advapi32
          .lookupFunction<
            Void Function(Pointer<Void>),
            void Function(Pointer<Void>)
          >('CredFree'),
      _getLastError = _kernel32
          .lookupFunction<Uint32 Function(), int Function()>('GetLastError');

  final int Function(Pointer<Utf16>, int, int) _credDelete;
  final int Function(Pointer<Utf16>, int, int, Pointer<Pointer<_Credential>>)
  _credRead;
  final int Function(Pointer<_Credential>, int) _credWrite;
  final void Function(Pointer<Void>) _credFree;
  final int Function() _getLastError;

  @override
  Future<bool> delete(String storageName, String logicalName) async {
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

  @override
  Future<String?> read(String storageName, String logicalName) async {
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
      return utf8.decode(blob);
    } finally {
      if (credPointer.value != nullptr) {
        _credFree(credPointer.value.cast<Void>());
      }
      calloc.free(credPointer);
      calloc.free(namePointer);
    }
  }

  @override
  Future<void> write(String storageName, String content) async {
    final passwordBytes = Uint8List.fromList(utf8.encode(content));
    final blob = passwordBytes.isEmpty
        ? nullptr
        : calloc<Uint8>(passwordBytes.length);
    if (blob != nullptr) {
      blob.asTypedList(passwordBytes.length).setAll(0, passwordBytes);
    }
    final namePointer = storageName.toNativeUtf16(allocator: calloc);
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
          'Error writing credential $storageName: ${_getLastError()}',
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
}

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
