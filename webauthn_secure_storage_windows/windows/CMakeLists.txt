cmake_minimum_required(VERSION 3.14)
set(PROJECT_NAME "webauthn_secure_storage_windows")
project(${PROJECT_NAME} LANGUAGES CXX)

cmake_policy(VERSION 3.14...3.24)

set(PLUGIN_NAME "${PROJECT_NAME}_plugin")

add_library(${PLUGIN_NAME} SHARED
  "webauthn_secure_storage_windows.cpp"
  "include/webauthn_secure_storage_windows/webauthn_secure_storage_windows_plugin_c_api.h"
  "webauthn_secure_storage_windows_plugin.cpp"
  "webauthn_secure_storage_windows_plugin.h"
)

apply_standard_settings(${PLUGIN_NAME})
set_target_properties(${PLUGIN_NAME} PROPERTIES CXX_VISIBILITY_PRESET hidden)
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)
target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(${PLUGIN_NAME} PRIVATE flutter flutter_wrapper_plugin runtimeobject)

set(webauthn_secure_storage_windows_bundled_libraries
  ""
  PARENT_SCOPE
)