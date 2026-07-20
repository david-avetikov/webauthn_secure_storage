import 'default_webauthn_runtime_stub.dart' if (dart.library.ui_web) 'default_webauthn_runtime_web.dart' as impl;
import 'webauthn_runtime.dart';

WebAuthnRuntime createDefaultWebAuthnRuntime() => impl.createDefaultWebAuthnRuntime();
