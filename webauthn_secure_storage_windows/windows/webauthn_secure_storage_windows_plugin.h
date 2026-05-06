#ifndef FLUTTER_PLUGIN_WEBAUTHN_SECURE_STORAGE_WINDOWS_PLUGIN_H_
#define FLUTTER_PLUGIN_WEBAUTHN_SECURE_STORAGE_WINDOWS_PLUGIN_H_

#include <windows.h>

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>
#include <string>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.UI.h>
#include <winrt/base.h>
#include <userconsentverifierinterop.h>

namespace webauthn_secure_storage_windows {

class WebauthnSecureStorageWindowsPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows* registrar);

  explicit WebauthnSecureStorageWindowsPlugin(
      flutter::PluginRegistrarWindows* registrar);

  ~WebauthnSecureStorageWindowsPlugin() override;

  WebauthnSecureStorageWindowsPlugin(
      const WebauthnSecureStorageWindowsPlugin&) = delete;
  WebauthnSecureStorageWindowsPlugin& operator=(
      const WebauthnSecureStorageWindowsPlugin&) = delete;

 private:
  HWND GetWindow() const;
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue>& method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);

  flutter::PluginRegistrarWindows* registrar_;
};

}  // namespace webauthn_secure_storage_windows

#endif  // FLUTTER_PLUGIN_WEBAUTHN_SECURE_STORAGE_WINDOWS_PLUGIN_H_