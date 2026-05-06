import 'package:flutter/services.dart';

enum WindowsUserConsentAvailability {
  available('Available'),
  deviceNotPresent('DeviceNotPresent'),
  notConfiguredForUser('NotConfiguredForUser'),
  disabledByPolicy('DisabledByPolicy'),
  deviceBusy('DeviceBusy'),
  unknown('Unknown');

  const WindowsUserConsentAvailability(this.nativeValue);

  final String nativeValue;

  static WindowsUserConsentAvailability fromNativeValue(String? value) {
    return WindowsUserConsentAvailability.values.firstWhere(
      (candidate) => candidate.nativeValue == value,
      orElse: () => WindowsUserConsentAvailability.unknown,
    );
  }
}

enum WindowsUserConsentVerificationResult {
  verified('Verified'),
  deviceNotPresent('DeviceNotPresent'),
  notConfiguredForUser('NotConfiguredForUser'),
  disabledByPolicy('DisabledByPolicy'),
  deviceBusy('DeviceBusy'),
  retriesExhausted('RetriesExhausted'),
  canceled('Canceled'),
  unknown('Unknown');

  const WindowsUserConsentVerificationResult(this.nativeValue);

  final String nativeValue;

  static WindowsUserConsentVerificationResult fromNativeValue(String? value) {
    return WindowsUserConsentVerificationResult.values.firstWhere(
      (candidate) => candidate.nativeValue == value,
      orElse: () => WindowsUserConsentVerificationResult.unknown,
    );
  }
}

abstract interface class WindowsUserConsentClient {
  Future<WindowsUserConsentAvailability> getAvailability();

  Future<WindowsUserConsentVerificationResult> requestVerification({
    required String reason,
  });
}

class MethodChannelWindowsUserConsentClient
    implements WindowsUserConsentClient {
  static const MethodChannel _channel = MethodChannel(
    'webauthn_secure_storage',
  );

  @override
  Future<WindowsUserConsentAvailability> getAvailability() async {
    final result = await _channel.invokeMethod<String>(
      'windowsGetUserConsentAvailability',
    );
    return WindowsUserConsentAvailability.fromNativeValue(result);
  }

  @override
  Future<WindowsUserConsentVerificationResult> requestVerification({
    required String reason,
  }) async {
    final result = await _channel.invokeMethod<String>(
      'windowsRequestUserConsentVerification',
      <String, dynamic>{'reason': reason},
    );
    return WindowsUserConsentVerificationResult.fromNativeValue(result);
  }
}
