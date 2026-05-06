cmake_minimum_required(VERSION 3.10)
set(PROJECT_NAME "webauthn_secure_storage_linux")
project(${PROJECT_NAME} LANGUAGES CXX)

set(PLUGIN_NAME "webauthn_secure_storage_linux_plugin")

add_library(${PLUGIN_NAME} SHARED
  "webauthn_secure_storage_plugin.cc"
)

find_package(PkgConfig REQUIRED)
pkg_check_modules (LIBSECRET REQUIRED IMPORTED_TARGET libsecret-1>=0.18)
pkg_check_modules (LIBFIDO2 REQUIRED IMPORTED_TARGET libfido2>=1.8.0)

apply_standard_settings(${PLUGIN_NAME})
set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden)
target_include_directories(${PLUGIN_NAME} PRIVATE ${LIBSECRET_INCLUDE_DIRS})
target_include_directories(${PLUGIN_NAME} PRIVATE ${LIBFIDO2_INCLUDE_DIRS})
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)
target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(${PLUGIN_NAME} PRIVATE flutter)
target_link_libraries(${PLUGIN_NAME} PRIVATE PkgConfig::GTK)
target_link_libraries(${PLUGIN_NAME} PRIVATE PkgConfig::LIBSECRET)
target_link_libraries(${PLUGIN_NAME} PRIVATE PkgConfig::LIBFIDO2)

set(webauthn_secure_storage_linux_bundled_libraries
  ""
  PARENT_SCOPE
)
