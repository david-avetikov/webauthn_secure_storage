#include "include/webauthn_secure_storage_linux/webauthn_secure_storage_plugin.h"

#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>
#include <gio/gio.h>
#include <libsecret/secret.h>
#include <fido.h>

#define BIOMETRIC_SCHEMA  biometric_get_schema ()

const char kBadArgumentsError[] = "Bad Arguments";
const char kSecurityAccessError[] = "Security Access Error";
const char kMethodRead[] = "read";
const char kMethodWrite[] = "write";
const char kMethodDelete[] = "delete";
const char kMethodExists[] = "exists";
const char kMethodGetPasskeyAvailability[] = "getPasskeyAvailability";
const char kMethodRegisterPasskey[] = "registerPasskey";
const char kMethodAuthenticateWithPasskey[] = "authenticateWithPasskey";
const char kNamePrefix[] = "webauthn_secure_storage";
const char kLegacyNamePrefix[] = "design.codeux.authpass";

static GQuark kPasskeyErrorQuark = 0;

typedef enum {
  kLookupStageCurrent = 0,
  kLookupStageLegacyPrefix = 1,
  kLookupStageLegacySchema = 2,
} LookupStage;

#define METHOD_PARAM_NAME(varName, prefix, args) \
  g_autofree gchar * varName = g_strdup_printf("%s.%s", prefix, fl_value_get_string(fl_value_lookup_string(args, "name")))

#define WEBAUTHN_SECURE_STORAGE_PLUGIN(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), webauthn_secure_storage_plugin_get_type(), \
                              WebauthnSecureStoragePlugin))

#define IS_METHOD(name, equals) \
  strcmp(method, equals) == 0

struct _WebauthnSecureStoragePlugin {
  GObject parent_instance;
  GHashTable *storage_authentication_required;
};

G_DEFINE_TYPE(WebauthnSecureStoragePlugin, webauthn_secure_storage_plugin, g_object_get_type())

typedef struct {
  FlMethodCall *method_call;
  gchar *entry_name;
  LookupStage stage;
} SecretLookupContext;

typedef struct {
  FlMethodCall *method_call;
  gchar *entry_name;
  LookupStage stage;
} SecretDeleteContext;

typedef enum {
  kFprintAvailabilityAvailable = 0,
  kFprintAvailabilityNoDevice = 1,
  kFprintAvailabilityNoEnrolled = 2,
  kFprintAvailabilityUnavailable = 3,
} FprintAvailability;

typedef struct {
  GMainLoop *loop;
  gchar *result;
  gboolean done;
} VerifyContext;

static const gchar kFprintService[] = "net.reactivated.Fprint";
static const gchar kFprintManagerPath[] = "/net/reactivated/Fprint/Manager";
static const gchar kFprintManagerInterface[] = "net.reactivated.Fprint.Manager";
static const gchar kFprintDeviceInterface[] = "net.reactivated.Fprint.Device";

static gboolean is_authentication_required(WebauthnSecureStoragePlugin *self, const gchar *entry_name) {
  gpointer value = g_hash_table_lookup(self->storage_authentication_required, entry_name);
  return GPOINTER_TO_INT(value) != 0;
}

static void remember_authentication_requirement(WebauthnSecureStoragePlugin *self, const gchar *entry_name, gboolean authentication_required) {
  g_hash_table_replace(
      self->storage_authentication_required,
      g_strdup(entry_name),
      GINT_TO_POINTER(authentication_required ? 1 : 0));
}

static FprintAvailability get_fprint_availability(GError **error) {
  g_autoptr(GDBusConnection) connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, error);
  if (connection == NULL) {
    return kFprintAvailabilityUnavailable;
  }

  g_autoptr(GVariant) manager_reply = g_dbus_connection_call_sync(
      connection,
      kFprintService,
      kFprintManagerPath,
      kFprintManagerInterface,
      "GetDefaultDevice",
      NULL,
      G_VARIANT_TYPE("(o)"),
      G_DBUS_CALL_FLAGS_NONE,
      -1,
      NULL,
      error);
  if (manager_reply == NULL) {
    if (error != NULL && *error != NULL && g_strrstr((*error)->message, "NoSuchDevice") != NULL) {
      return kFprintAvailabilityNoDevice;
    }
    return kFprintAvailabilityUnavailable;
  }

  const gchar *device_path = NULL;
  g_variant_get(manager_reply, "(&o)", &device_path);

  g_autoptr(GVariant) enrolled_reply = g_dbus_connection_call_sync(
      connection,
      kFprintService,
      device_path,
      kFprintDeviceInterface,
      "ListEnrolledFingers",
      g_variant_new("(s)", ""),
      G_VARIANT_TYPE("(as)"),
      G_DBUS_CALL_FLAGS_NONE,
      -1,
      NULL,
      error);
  if (enrolled_reply == NULL) {
    if (error != NULL && *error != NULL && g_strrstr((*error)->message, "NoEnrolledPrints") != NULL) {
      return kFprintAvailabilityNoEnrolled;
    }
    return kFprintAvailabilityUnavailable;
  }

  return kFprintAvailabilityAvailable;
}

static void on_verify_status(
    GDBusConnection *connection,
    const gchar *sender_name,
    const gchar *object_path,
    const gchar *interface_name,
    const gchar *signal_name,
    GVariant *parameters,
    gpointer user_data) {
  VerifyContext *context = (VerifyContext *)user_data;
  const gchar *result = NULL;
  gboolean done = FALSE;
  g_variant_get(parameters, "(&sb)", &result, &done);
  g_free(context->result);
  context->result = g_strdup(result);
  context->done = done;
  if (done) {
    g_main_loop_quit(context->loop);
  }
}

static gboolean perform_fingerprint_verification(GError **error) {
  g_autoptr(GDBusConnection) connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, error);
  if (connection == NULL) {
    return FALSE;
  }

  g_autoptr(GVariant) manager_reply = g_dbus_connection_call_sync(
      connection,
      kFprintService,
      kFprintManagerPath,
      kFprintManagerInterface,
      "GetDefaultDevice",
      NULL,
      G_VARIANT_TYPE("(o)"),
      G_DBUS_CALL_FLAGS_NONE,
      -1,
      NULL,
      error);
  if (manager_reply == NULL) {
    return FALSE;
  }

  const gchar *device_path = NULL;
  g_variant_get(manager_reply, "(&o)", &device_path);

  g_autoptr(GVariant) claim_reply = g_dbus_connection_call_sync(
      connection,
      kFprintService,
      device_path,
      kFprintDeviceInterface,
      "Claim",
      g_variant_new("(s)", ""),
      NULL,
      G_DBUS_CALL_FLAGS_NONE,
      -1,
      NULL,
      error);
  if (claim_reply == NULL) {
    return FALSE;
  }

  VerifyContext context = {};
  context.loop = g_main_loop_new(NULL, FALSE);
  guint signal_subscription = g_dbus_connection_signal_subscribe(
      connection,
      kFprintService,
      kFprintDeviceInterface,
      "VerifyStatus",
      device_path,
      NULL,
      G_DBUS_SIGNAL_FLAGS_NONE,
      on_verify_status,
      &context,
      NULL);

  g_autoptr(GVariant) verify_reply = g_dbus_connection_call_sync(
      connection,
      kFprintService,
      device_path,
      kFprintDeviceInterface,
      "VerifyStart",
      g_variant_new("(s)", "any"),
      NULL,
      G_DBUS_CALL_FLAGS_NONE,
      -1,
      NULL,
      error);
  if (verify_reply != NULL) {
    g_main_loop_run(context.loop);
  }

  g_dbus_connection_signal_unsubscribe(connection, signal_subscription);

  g_dbus_connection_call_sync(
      connection,
      kFprintService,
      device_path,
      kFprintDeviceInterface,
      "VerifyStop",
      NULL,
      NULL,
      G_DBUS_CALL_FLAGS_NONE,
      -1,
      NULL,
      NULL);
  g_dbus_connection_call_sync(
      connection,
      kFprintService,
      device_path,
      kFprintDeviceInterface,
      "Release",
      NULL,
      NULL,
      G_DBUS_CALL_FLAGS_NONE,
      -1,
      NULL,
      NULL);

  gboolean success = context.result != NULL && g_strcmp0(context.result, "verify-match") == 0;
  if (!success && error != NULL && *error == NULL && context.result != NULL) {
    *error = g_error_new_literal(g_quark_from_static_string("fprintd"), 0, context.result);
  }

  if (context.loop != NULL) {
    g_main_loop_unref(context.loop);
  }
  g_free(context.result);

  return success;
}

static FlMethodResponse *biometric_response_if_needed(
    WebauthnSecureStoragePlugin *self,
    FlMethodCall *method_call,
    FlValue *args,
    const gchar *entry_name) {
  FlValue *force_value = fl_value_lookup_string(args, "forceBiometricAuthentication");
  gboolean force_biometric = force_value != NULL && fl_value_get_bool(force_value);
  if (!force_biometric && !is_authentication_required(self, entry_name)) {
    return NULL;
  }

  GError *error = NULL;
  gboolean verified = perform_fingerprint_verification(&error);
  if (verified) {
    return NULL;
  }

  if (error != NULL) {
    const gchar *message = error->message == NULL ? "Fingerprint verification failed." : error->message;
    FlMethodResponse *response = FL_METHOD_RESPONSE(fl_method_error_response_new(
        "AuthError:Canceled",
        message,
        NULL));
    g_error_free(error);
    return response;
  }

  return FL_METHOD_RESPONSE(fl_method_error_response_new(
      "AuthError:Canceled",
      "Fingerprint verification failed.",
      NULL));
}

static SecretLookupContext *secret_lookup_context_new(FlMethodCall *method_call, const gchar *entry_name) {
  SecretLookupContext *context = g_new0(SecretLookupContext, 1);
  context->method_call = g_object_ref(method_call);
  context->entry_name = g_strdup(entry_name);
  return context;
}

static void secret_lookup_context_free(SecretLookupContext *context) {
  g_clear_object(&context->method_call);
  g_free(context->entry_name);
  g_free(context);
}

static SecretDeleteContext *secret_delete_context_new(FlMethodCall *method_call, const gchar *entry_name) {
  SecretDeleteContext *context = g_new0(SecretDeleteContext, 1);
  context->method_call = g_object_ref(method_call);
  context->entry_name = g_strdup(entry_name);
  return context;
}

static void secret_delete_context_free(SecretDeleteContext *context) {
  g_clear_object(&context->method_call);
  g_free(context->entry_name);
  g_free(context);
}

static FlMethodResponse *bad_arguments_response(const gchar *message) {
  return FL_METHOD_RESPONSE(fl_method_error_response_new(
      kBadArgumentsError,
      message,
      nullptr));
}

static FlMethodResponse *passkey_error_response(const gchar *message) {
  return FL_METHOD_RESPONSE(fl_method_error_response_new(
      "AuthError:Unknown",
      message,
      nullptr));
}

static FlMethodResponse *passkey_error_response_from_gerror(
    const gchar *fallback_message,
    GError *error) {
  const gchar *message =
      error != NULL && error->message != NULL ? error->message : fallback_message;
  return FL_METHOD_RESPONSE(fl_method_error_response_new(
      "AuthError:Unknown",
      message,
      nullptr));
}

static gboolean ensure_passkey_error_quark(void) {
  if (kPasskeyErrorQuark == 0) {
    kPasskeyErrorQuark = g_quark_from_static_string(
        "webauthn_secure_storage_passkey");
  }
  return TRUE;
}

static gboolean set_passkey_error(
    GError **error,
    const gchar *format,
    ...) {
  ensure_passkey_error_quark();
  va_list arguments;
  va_start(arguments, format);
  g_autofree gchar *message = g_strdup_vprintf(format, arguments);
  va_end(arguments);
  g_set_error(error, kPasskeyErrorQuark, 0, "%s", message);
  return FALSE;
}

static gboolean copy_flvalue_bytes(
    FlValue *value,
    guchar **out_bytes,
    gsize *out_length,
    GError **error) {
  if (value == NULL) {
    return set_passkey_error(error, "Binary value was missing.");
  }

  const FlValueType type = fl_value_get_type(value);
  if (type == FL_VALUE_TYPE_UINT8_LIST) {
    const gsize length = fl_value_get_length(value);
    const uint8_t *source = fl_value_get_uint8_list(value);
    guchar *bytes = static_cast<guchar *>(g_malloc(length == 0 ? 1 : length));
    if (length > 0) {
      memcpy(bytes, source, length);
    }
    *out_bytes = bytes;
    *out_length = length;
    return TRUE;
  }

  if (type == FL_VALUE_TYPE_LIST) {
    const gsize length = fl_value_get_length(value);
    guchar *bytes = static_cast<guchar *>(g_malloc(length == 0 ? 1 : length));
    for (gsize index = 0; index < length; index++) {
      FlValue *entry = fl_value_get_list_value(value, index);
      if (entry == NULL || fl_value_get_type(entry) != FL_VALUE_TYPE_INT) {
        g_free(bytes);
        return set_passkey_error(
            error,
            "Binary list contained a non-integer element at index %zu.",
            index);
      }
      const int64_t component = fl_value_get_int(entry);
      if (component < 0 || component > 255) {
        g_free(bytes);
        return set_passkey_error(
            error,
            "Binary list element at index %zu was outside byte range.",
            index);
      }
      bytes[index] = static_cast<guchar>(component);
    }
    *out_bytes = bytes;
    *out_length = length;
    return TRUE;
  }

  return set_passkey_error(
      error,
      "Expected binary value but received Flutter value type %d.",
      type);
}

static gboolean decode_base64url(
    const gchar *value,
    guchar **out_bytes,
    gsize *out_length,
    GError **error) {
  if (value == NULL) {
    return set_passkey_error(error, "Base64url value was missing.");
  }

  g_autoptr(GString) normalized = g_string_new(value);
  for (gsize index = 0; index < normalized->len; index++) {
    if (normalized->str[index] == '-') {
      normalized->str[index] = '+';
    } else if (normalized->str[index] == '_') {
      normalized->str[index] = '/';
    }
  }

  const gsize remainder = normalized->len % 4;
  if (remainder != 0) {
    for (gsize padding = 0; padding < 4 - remainder; padding++) {
      g_string_append_c(normalized, '=');
    }
  }

  gsize decoded_length = 0;
  guchar *decoded = g_base64_decode(normalized->str, &decoded_length);
  if (decoded == NULL) {
    return set_passkey_error(error, "Failed to decode base64url payload.");
  }

  *out_bytes = decoded;
  *out_length = decoded_length;
  return TRUE;
}

static gboolean compute_sha256(
    const guchar *bytes,
    gsize length,
    guchar out_digest[32],
    GError **error) {
  g_autoptr(GChecksum) checksum = g_checksum_new(G_CHECKSUM_SHA256);
  if (checksum == NULL) {
    return set_passkey_error(error, "Failed to allocate SHA-256 checksum state.");
  }

  g_checksum_update(checksum, bytes, length);
  gsize digest_length = 32;
  g_checksum_get_digest(checksum, out_digest, &digest_length);
  if (digest_length != 32) {
    return set_passkey_error(error, "Failed to compute a SHA-256 digest.");
  }

  return TRUE;
}

static fido_opt_t user_verification_to_opt(const gchar *value) {
  if (value == NULL) {
    return FIDO_OPT_OMIT;
  }
  if (g_strcmp0(value, "required") == 0 ||
      g_strcmp0(value, "preferred") == 0) {
    return FIDO_OPT_TRUE;
  }
  if (g_strcmp0(value, "discouraged") == 0) {
    return FIDO_OPT_FALSE;
  }
  return FIDO_OPT_OMIT;
}

static fido_opt_t resident_key_to_opt(
    const gchar *resident_key,
    gboolean require_resident_key) {
  if (require_resident_key || g_strcmp0(resident_key, "required") == 0 ||
      g_strcmp0(resident_key, "preferred") == 0) {
    return FIDO_OPT_TRUE;
  }
  if (g_strcmp0(resident_key, "discouraged") == 0) {
    return FIDO_OPT_FALSE;
  }
  return FIDO_OPT_OMIT;
}

static gboolean open_first_fido2_device(
    fido_dev_t **out_device,
    gchar **out_manufacturer,
    gchar **out_product,
    GError **error) {
  fido_dev_info_t *device_list = fido_dev_info_new(16);
  if (device_list == NULL) {
    return set_passkey_error(error, "Failed to allocate FIDO device list.");
  }

  size_t discovered_devices = 0;
  const int manifest_result =
      fido_dev_info_manifest(device_list, 16, &discovered_devices);
  if (manifest_result != FIDO_OK) {
    fido_dev_info_free(&device_list, 16);
    return set_passkey_error(
        error,
        "Failed to enumerate FIDO devices: %s.",
        fido_strerr(manifest_result));
  }

  for (size_t index = 0; index < discovered_devices; index++) {
    const fido_dev_info_t *device_info = fido_dev_info_ptr(device_list, index);
    const char *path = fido_dev_info_path(device_info);
    if (path == NULL || *path == '\0') {
      continue;
    }

    fido_dev_t *device = fido_dev_new();
    if (device == NULL) {
      continue;
    }

    const int open_result = fido_dev_open(device, path);
    if (open_result != FIDO_OK || !fido_dev_is_fido2(device)) {
      if (open_result == FIDO_OK) {
        fido_dev_close(device);
      }
      fido_dev_free(&device);
      continue;
    }

    if (out_manufacturer != NULL) {
      *out_manufacturer = g_strdup(fido_dev_info_manufacturer_string(device_info));
    }
    if (out_product != NULL) {
      *out_product = g_strdup(fido_dev_info_product_string(device_info));
    }

    *out_device = device;
    fido_dev_info_free(&device_list, 16);
    return TRUE;
  }

  fido_dev_info_free(&device_list, 16);
  return set_passkey_error(
      error,
      "No compatible FIDO2 authenticator was available on this system.");
}

static void set_map_bool(FlValue *map, const gchar *key, gboolean value) {
  fl_value_set_string_take(map, key, fl_value_new_bool(value));
}

static void set_map_int(FlValue *map, const gchar *key, int64_t value) {
  fl_value_set_string_take(map, key, fl_value_new_int(value));
}

static void set_map_string_if_present(
    FlValue *map,
    const gchar *key,
    const gchar *value) {
  if (value != NULL && *value != '\0') {
    fl_value_set_string_take(map, key, fl_value_new_string(value));
  }
}

static void set_map_bytes(
    FlValue *map,
    const gchar *key,
    const unsigned char *value,
    size_t length) {
  fl_value_set_string_take(map, key, fl_value_new_uint8_list(value, length));
}

static FlMethodResponse *handle_get_passkey_availability(void) {
  GError *error = NULL;
  fido_dev_t *device = NULL;
  g_autofree gchar *manufacturer = NULL;
  g_autofree gchar *product = NULL;
  gboolean available = open_first_fido2_device(
      &device,
      &manufacturer,
      &product,
      &error);

  g_autoptr(FlValue) result = fl_value_new_map();
  set_map_bool(result, "isSupported", TRUE);
  set_map_bool(result, "isAvailable", available);
  set_map_bool(result, "hasPlatformAuthenticator", FALSE);
  set_map_bool(result, "hasConditionalUi", FALSE);
  set_map_bool(result, "supportsPrfStorage", FALSE);
  set_map_bool(result, "isPrfStorageAvailable", FALSE);

  g_autoptr(FlValue) metadata = fl_value_new_map();
  set_map_string_if_present(metadata, "manufacturer", manufacturer);
  set_map_string_if_present(metadata, "product", product);

  if (available && device != NULL) {
    set_map_bool(result, "hasDiscoverableCredentials", fido_dev_supports_credman(device));
    set_map_bool(result, "hasPendingRegistrationOpportunity", TRUE);
    set_map_bool(metadata, "supportsUserVerification", fido_dev_supports_uv(device));
    set_map_bool(metadata, "hasUserVerification", fido_dev_has_uv(device));
  } else {
    set_map_bool(result, "hasDiscoverableCredentials", FALSE);
    set_map_bool(result, "hasPendingRegistrationOpportunity", FALSE);
    if (error != NULL && error->message != NULL) {
      set_map_string_if_present(metadata, "unavailableReason", error->message);
    }
  }

  if (fl_value_get_length(metadata) > 0) {
    fl_value_set_string_take(result, "metadata", metadata);
  }

  if (device != NULL) {
    fido_dev_close(device);
    fido_dev_free(&device);
  }
  if (error != NULL) {
    g_error_free(error);
  }

  return FL_METHOD_RESPONSE(fl_method_success_response_new(result));
}

static FlMethodResponse *handle_register_passkey(FlValue *args) {
  FlValue *options = fl_value_lookup_string(args, "options");
  FlValue *client_data_json_value = fl_value_lookup_string(args, "clientDataJson");
  if (options == NULL || fl_value_get_type(options) != FL_VALUE_TYPE_MAP) {
    return bad_arguments_response("registerPasskey expected an options map.");
  }
  if (client_data_json_value == NULL) {
    return bad_arguments_response("registerPasskey expected clientDataJson bytes.");
  }

  FlValue *rp = fl_value_lookup_string(options, "rp");
  FlValue *user = fl_value_lookup_string(options, "user");
  FlValue *pub_key_cred_params = fl_value_lookup_string(options, "pubKeyCredParams");
  if (rp == NULL || fl_value_get_type(rp) != FL_VALUE_TYPE_MAP ||
      user == NULL || fl_value_get_type(user) != FL_VALUE_TYPE_MAP ||
      pub_key_cred_params == NULL ||
          fl_value_get_type(pub_key_cred_params) != FL_VALUE_TYPE_LIST) {
    return bad_arguments_response(
        "registerPasskey options were missing rp, user, or pubKeyCredParams.");
  }

  const gchar *rp_name = fl_value_get_string(fl_value_lookup_string(rp, "name"));
  const gchar *rp_id = fl_value_get_string(fl_value_lookup_string(rp, "id"));
  if (rp_id == NULL || *rp_id == '\0') {
    rp_id = rp_name;
  }
  const gchar *user_name = fl_value_get_string(fl_value_lookup_string(user, "name"));
  const gchar *display_name = fl_value_get_string(fl_value_lookup_string(user, "displayName"));
  const gchar *user_id_base64 = fl_value_get_string(fl_value_lookup_string(user, "id"));
  if (rp_id == NULL || *rp_id == '\0' || rp_name == NULL || *rp_name == '\0' ||
      user_name == NULL || *user_name == '\0' || display_name == NULL ||
      *display_name == '\0' || user_id_base64 == NULL || *user_id_base64 == '\0') {
    return bad_arguments_response(
        "registerPasskey options contained incomplete RP or user fields.");
  }

  g_autofree guchar *client_data_json = NULL;
  gsize client_data_json_length = 0;
  g_autofree guchar *user_id = NULL;
  gsize user_id_length = 0;
  GError *error = NULL;

  if (!copy_flvalue_bytes(
          client_data_json_value,
          &client_data_json,
          &client_data_json_length,
          &error)) {
    FlMethodResponse *response = passkey_error_response_from_gerror(
        "Invalid clientDataJson payload.", error);
    g_clear_error(&error);
    return response;
  }
  if (!decode_base64url(user_id_base64, &user_id, &user_id_length, &error)) {
    FlMethodResponse *response = passkey_error_response_from_gerror(
        "Invalid user identifier.", error);
    g_clear_error(&error);
    return response;
  }

  guchar client_data_hash[32];
  if (!compute_sha256(
          client_data_json,
          client_data_json_length,
          client_data_hash,
          &error)) {
    FlMethodResponse *response = passkey_error_response_from_gerror(
        "Failed to hash clientDataJson.", error);
    g_clear_error(&error);
    return response;
  }

  int cose_algorithm = -7;
  const gsize algorithm_count = fl_value_get_length(pub_key_cred_params);
  for (gsize index = 0; index < algorithm_count; index++) {
    FlValue *parameter = fl_value_get_list_value(pub_key_cred_params, index);
    if (parameter == NULL || fl_value_get_type(parameter) != FL_VALUE_TYPE_MAP) {
      continue;
    }
    FlValue *type_value = fl_value_lookup_string(parameter, "type");
    FlValue *alg_value = fl_value_lookup_string(parameter, "alg");
    if (type_value != NULL && fl_value_get_type(type_value) == FL_VALUE_TYPE_STRING &&
        g_strcmp0(fl_value_get_string(type_value), "public-key") == 0 &&
        alg_value != NULL && fl_value_get_type(alg_value) == FL_VALUE_TYPE_INT) {
      cose_algorithm = static_cast<int>(fl_value_get_int(alg_value));
      break;
    }
  }

  FlValue *authenticator_selection =
      fl_value_lookup_string(options, "authenticatorSelection");
  const gchar *resident_key = NULL;
  gboolean require_resident_key = FALSE;
  const gchar *user_verification = NULL;
  if (authenticator_selection != NULL &&
      fl_value_get_type(authenticator_selection) == FL_VALUE_TYPE_MAP) {
    FlValue *resident_key_value =
        fl_value_lookup_string(authenticator_selection, "residentKey");
    if (resident_key_value != NULL &&
        fl_value_get_type(resident_key_value) == FL_VALUE_TYPE_STRING) {
      resident_key = fl_value_get_string(resident_key_value);
    }
    FlValue *require_resident_key_value =
        fl_value_lookup_string(authenticator_selection, "requireResidentKey");
    if (require_resident_key_value != NULL &&
        fl_value_get_type(require_resident_key_value) == FL_VALUE_TYPE_BOOL) {
      require_resident_key = fl_value_get_bool(require_resident_key_value);
    }
    FlValue *user_verification_value =
        fl_value_lookup_string(authenticator_selection, "userVerification");
    if (user_verification_value != NULL &&
        fl_value_get_type(user_verification_value) == FL_VALUE_TYPE_STRING) {
      user_verification = fl_value_get_string(user_verification_value);
    }
  }

  fido_dev_t *device = NULL;
  if (!open_first_fido2_device(&device, NULL, NULL, &error)) {
    FlMethodResponse *response = passkey_error_response_from_gerror(
        "No FIDO2 authenticator was available.", error);
    g_clear_error(&error);
    return response;
  }

  fido_cred_t *credential = fido_cred_new();
  if (credential == NULL) {
    fido_dev_close(device);
    fido_dev_free(&device);
    return passkey_error_response("Failed to allocate a FIDO credential request.");
  }

  int fido_status = FIDO_OK;
  fido_status = fido_cred_set_type(credential, cose_algorithm);
  if (fido_status == FIDO_OK) {
    fido_status = fido_cred_set_clientdata_hash(
        credential, client_data_hash, sizeof(client_data_hash));
  }
  if (fido_status == FIDO_OK) {
    fido_status = fido_cred_set_rp(credential, rp_id, rp_name);
  }
  if (fido_status == FIDO_OK) {
    fido_status = fido_cred_set_user(
        credential,
        user_id,
        user_id_length,
        user_name,
        display_name,
        NULL);
  }
  if (fido_status == FIDO_OK) {
    fido_status = fido_cred_set_rk(
        credential,
        resident_key_to_opt(resident_key, require_resident_key));
  }
  if (fido_status == FIDO_OK) {
    fido_status = fido_cred_set_uv(
        credential,
        user_verification_to_opt(user_verification));
  }

  FlValue *exclude_credentials = fl_value_lookup_string(options, "excludeCredentials");
  if (fido_status == FIDO_OK && exclude_credentials != NULL &&
      fl_value_get_type(exclude_credentials) == FL_VALUE_TYPE_LIST) {
    const gsize excluded_count = fl_value_get_length(exclude_credentials);
    for (gsize index = 0; index < excluded_count && fido_status == FIDO_OK; index++) {
      FlValue *descriptor = fl_value_get_list_value(exclude_credentials, index);
      if (descriptor == NULL || fl_value_get_type(descriptor) != FL_VALUE_TYPE_MAP) {
        fido_status = FIDO_ERR_INVALID_ARGUMENT;
        break;
      }
      const gchar *credential_id_base64 =
          fl_value_get_string(fl_value_lookup_string(descriptor, "id"));
      g_autofree guchar *credential_id = NULL;
      gsize credential_id_length = 0;
      if (!decode_base64url(
              credential_id_base64,
              &credential_id,
              &credential_id_length,
              &error)) {
        fido_status = FIDO_ERR_INVALID_ARGUMENT;
        break;
      }
      fido_status = fido_cred_exclude(
          credential,
          credential_id,
          credential_id_length);
    }
  }

  if (fido_status == FIDO_OK) {
    fido_status = fido_dev_make_cred(device, credential, NULL);
  }

  if (fido_status != FIDO_OK) {
    gchar *message = g_strdup_printf(
        "Passkey registration failed: %s.",
        fido_strerr(fido_status));
    FlMethodResponse *response = passkey_error_response(message);
    g_free(message);
    if (error != NULL) {
      g_clear_error(&error);
    }
    fido_cred_free(&credential);
    fido_dev_close(device);
    fido_dev_free(&device);
    return response;
  }

  g_autoptr(FlValue) result = fl_value_new_map();
  set_map_bytes(
      result,
      "credentialId",
      fido_cred_id_ptr(credential),
      fido_cred_id_len(credential));
  set_map_bytes(
      result,
      "authenticatorData",
      fido_cred_authdata_raw_ptr(credential),
      fido_cred_authdata_raw_len(credential));
  set_map_bytes(
      result,
      "attestationStatement",
      fido_cred_attstmt_ptr(credential),
      fido_cred_attstmt_len(credential));
  if (fido_cred_pubkey_ptr(credential) != NULL) {
    set_map_bytes(
        result,
        "publicKey",
        fido_cred_pubkey_ptr(credential),
        fido_cred_pubkey_len(credential));
  }
  set_map_int(result, "publicKeyAlgorithm", fido_cred_type(credential));
  set_map_string_if_present(result, "format", fido_cred_fmt(credential));
  fl_value_set_string_take(result, "authenticatorAttachment", fl_value_new_string("cross-platform"));
  g_autoptr(FlValue) transports = fl_value_new_list();
  fl_value_append_take(transports, fl_value_new_string("usb"));
  fl_value_set_string_take(result, "transports", transports);

  fido_cred_free(&credential);
  fido_dev_close(device);
  fido_dev_free(&device);
  if (error != NULL) {
    g_clear_error(&error);
  }
  return FL_METHOD_RESPONSE(fl_method_success_response_new(result));
}

static FlMethodResponse *handle_authenticate_with_passkey(FlValue *args) {
  FlValue *options = fl_value_lookup_string(args, "options");
  FlValue *client_data_json_value = fl_value_lookup_string(args, "clientDataJson");
  if (options == NULL || fl_value_get_type(options) != FL_VALUE_TYPE_MAP) {
    return bad_arguments_response(
        "authenticateWithPasskey expected an options map.");
  }
  if (client_data_json_value == NULL) {
    return bad_arguments_response(
        "authenticateWithPasskey expected clientDataJson bytes.");
  }

  const gchar *rp_id = fl_value_get_string(fl_value_lookup_string(options, "rpId"));
  if (rp_id == NULL || *rp_id == '\0') {
    return bad_arguments_response(
        "authenticateWithPasskey requires a non-empty rpId.");
  }

  GError *error = NULL;
  g_autofree guchar *client_data_json = NULL;
  gsize client_data_json_length = 0;
  if (!copy_flvalue_bytes(
          client_data_json_value,
          &client_data_json,
          &client_data_json_length,
          &error)) {
    FlMethodResponse *response = passkey_error_response_from_gerror(
        "Invalid clientDataJson payload.", error);
    g_clear_error(&error);
    return response;
  }

  guchar client_data_hash[32];
  if (!compute_sha256(
          client_data_json,
          client_data_json_length,
          client_data_hash,
          &error)) {
    FlMethodResponse *response = passkey_error_response_from_gerror(
        "Failed to hash clientDataJson.", error);
    g_clear_error(&error);
    return response;
  }

  fido_dev_t *device = NULL;
  if (!open_first_fido2_device(&device, NULL, NULL, &error)) {
    FlMethodResponse *response = passkey_error_response_from_gerror(
        "No FIDO2 authenticator was available.", error);
    g_clear_error(&error);
    return response;
  }

  fido_assert_t *assertion = fido_assert_new();
  if (assertion == NULL) {
    fido_dev_close(device);
    fido_dev_free(&device);
    return passkey_error_response("Failed to allocate a FIDO assertion request.");
  }

  int fido_status = fido_assert_set_clientdata_hash(
      assertion,
      client_data_hash,
      sizeof(client_data_hash));
  if (fido_status == FIDO_OK) {
    fido_status = fido_assert_set_rp(assertion, rp_id);
  }

  const gchar *user_verification =
      fl_value_get_string(fl_value_lookup_string(options, "userVerification"));
  if (fido_status == FIDO_OK) {
    fido_status = fido_assert_set_uv(
        assertion,
        user_verification_to_opt(user_verification));
  }

  FlValue *allow_credentials = fl_value_lookup_string(options, "allowCredentials");
  if (fido_status == FIDO_OK && allow_credentials != NULL &&
      fl_value_get_type(allow_credentials) == FL_VALUE_TYPE_LIST) {
    const gsize allowed_count = fl_value_get_length(allow_credentials);
    for (gsize index = 0; index < allowed_count && fido_status == FIDO_OK; index++) {
      FlValue *descriptor = fl_value_get_list_value(allow_credentials, index);
      if (descriptor == NULL || fl_value_get_type(descriptor) != FL_VALUE_TYPE_MAP) {
        fido_status = FIDO_ERR_INVALID_ARGUMENT;
        break;
      }
      const gchar *credential_id_base64 =
          fl_value_get_string(fl_value_lookup_string(descriptor, "id"));
      g_autofree guchar *credential_id = NULL;
      gsize credential_id_length = 0;
      if (!decode_base64url(
              credential_id_base64,
              &credential_id,
              &credential_id_length,
              &error)) {
        fido_status = FIDO_ERR_INVALID_ARGUMENT;
        break;
      }
      fido_status = fido_assert_allow_cred(
          assertion,
          credential_id,
          credential_id_length);
    }
  }

  if (fido_status == FIDO_OK) {
    fido_status = fido_dev_get_assert(device, assertion, NULL);
  }

  if (fido_status != FIDO_OK || fido_assert_count(assertion) == 0) {
    gchar *message = g_strdup_printf(
        "Passkey authentication failed: %s.",
        fido_strerr(fido_status));
    FlMethodResponse *response = passkey_error_response(message);
    g_free(message);
    if (error != NULL) {
      g_clear_error(&error);
    }
    fido_assert_free(&assertion);
    fido_dev_close(device);
    fido_dev_free(&device);
    return response;
  }

  g_autoptr(FlValue) result = fl_value_new_map();
  set_map_bytes(
      result,
      "credentialId",
      fido_assert_id_ptr(assertion, 0),
      fido_assert_id_len(assertion, 0));
  set_map_bytes(
      result,
      "authenticatorData",
      fido_assert_authdata_raw_ptr(assertion, 0),
      fido_assert_authdata_raw_len(assertion, 0));
  set_map_bytes(
      result,
      "signature",
      fido_assert_sig_ptr(assertion, 0),
      fido_assert_sig_len(assertion, 0));
  if (fido_assert_user_id_ptr(assertion, 0) != NULL) {
    set_map_bytes(
        result,
        "userHandle",
        fido_assert_user_id_ptr(assertion, 0),
        fido_assert_user_id_len(assertion, 0));
  }
  fl_value_set_string_take(result, "authenticatorAttachment", fl_value_new_string("cross-platform"));

  fido_assert_free(&assertion);
  fido_dev_close(device);
  fido_dev_free(&device);
  if (error != NULL) {
    g_clear_error(&error);
  }
  return FL_METHOD_RESPONSE(fl_method_success_response_new(result));
}

static FlMethodResponse* _handle_error(const gchar* message, GError *error) {
    const gchar* domain = g_quark_to_string(error->domain);
    g_autofree gchar *error_message = g_strdup_printf("%s: %s (%d) (%s)", message, error->message, error->code, domain);
    g_warning("%s", error_message);
    g_autoptr(FlValue) error_details = fl_value_new_map();
    fl_value_set_string_take(error_details, "domain", fl_value_new_string(domain));
    fl_value_set_string_take(error_details, "code", fl_value_new_int(error->code));
    fl_value_set_string_take(error_details, "message", fl_value_new_string(error->message));
    return FL_METHOD_RESPONSE(fl_method_error_response_new(
                   kSecurityAccessError, error_message, error_details));
}

static FlMethodResponse *handleInit(WebauthnSecureStoragePlugin *self, FlValue *args) {
  FlValue* options = fl_value_lookup_string(args, "options");
  if (fl_value_get_type(options) != FL_VALUE_TYPE_MAP) {
    return FL_METHOD_RESPONSE(fl_method_error_response_new(
        kBadArgumentsError, "Argument map missing or malformed", nullptr));
  }
  const gchar *entry_name = fl_value_get_string(fl_value_lookup_string(args, "name"));
  FlValue* authRequired = fl_value_lookup_string(options, "authenticationRequired");
  gboolean authentication_required = authRequired != NULL && fl_value_get_bool(authRequired);
  remember_authentication_requirement(self, entry_name, authentication_required);
  if (authentication_required) {
    GError *error = NULL;
    FprintAvailability availability = get_fprint_availability(&error);
    if (error != NULL) {
      g_error_free(error);
    }
    if (availability == kFprintAvailabilityNoDevice || availability == kFprintAvailabilityUnavailable) {
      return FL_METHOD_RESPONSE(fl_method_error_response_new(
          kSecurityAccessError,
          "Linux biometric-gated storage requires fprintd and an available fingerprint reader.",
          nullptr));
    }
  }
  return FL_METHOD_RESPONSE(fl_method_success_response_new(fl_value_new_bool(true)));
}

const SecretSchema * biometric_get_schema (void) {
    static const SecretSchema the_schema = {
        "dev.webauthn_secure_storage", SECRET_SCHEMA_NONE,
        {
            {  "name", SECRET_SCHEMA_ATTRIBUTE_STRING },
        }
    };
    return &the_schema;
}

const SecretSchema * biometric_legacy_schema (void) {
  static const SecretSchema legacy_schema = {
    "design.codeux.BiometricStorage", SECRET_SCHEMA_NONE,
    {
      {  "name", SECRET_SCHEMA_ATTRIBUTE_STRING },
    }
  };
  return &legacy_schema;
}

static const SecretSchema * schema_for_stage(LookupStage stage) {
  return stage == kLookupStageLegacySchema ? biometric_legacy_schema() : BIOMETRIC_SCHEMA;
}

static gchar * entry_name_for_stage(LookupStage stage, const gchar *entry_name) {
  const gchar *prefix = stage == kLookupStageCurrent ? kNamePrefix : kLegacyNamePrefix;
  return g_strdup_printf("%s.%s", prefix, entry_name);
}

static void on_password_stored(GObject *source, GAsyncResult *result, gpointer user_data) {
  GError *error = NULL;
  FlMethodCall *method_call = (FlMethodCall *)user_data;
  g_autoptr(FlMethodResponse) response = nullptr;

  secret_password_store_finish(result, &error);
  if (error != NULL) {
    response = _handle_error("Failed to store secret", error);
    g_error_free(error);
  } else {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(fl_value_new_bool(true)));
  }

  fl_method_call_respond(method_call, response, nullptr);
  g_object_unref(method_call);
}

static void on_password_cleared(GObject *source, GAsyncResult *result, gpointer user_data) {
  GError *error = NULL;
  SecretDeleteContext *context = (SecretDeleteContext *)user_data;
  g_autoptr(FlMethodResponse) response = nullptr;

  gboolean removed = secret_password_clear_finish(result, &error);

  if (error != NULL) {
    response = _handle_error("Failed to delete secret", error);
    g_error_free(error);
  } else if (!removed && context->stage != kLookupStageLegacySchema) {
    context->stage = (LookupStage)(context->stage + 1);
    g_autofree gchar *legacy_name = entry_name_for_stage(context->stage, context->entry_name);
    secret_password_clear(schema_for_stage(context->stage), NULL, on_password_cleared,
                          context, "name", legacy_name, NULL);
    return;
  } else {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(fl_value_new_bool(removed)));
  }
  fl_method_call_respond(context->method_call, response, nullptr);
  secret_delete_context_free(context);
}

static void on_password_lookup(GObject *source, GAsyncResult *result, gpointer user_data) {
  GError *error = NULL;
  SecretLookupContext *context = (SecretLookupContext *)user_data;
  g_autoptr(FlMethodResponse) response = nullptr;

  gchar *password = secret_password_lookup_finish(result, &error);

  if (error != NULL) {
    response = _handle_error("Failed to lookup secret", error);
    g_error_free(error);
  } else if (password == NULL && context->stage != kLookupStageLegacySchema) {
    context->stage = (LookupStage)(context->stage + 1);
    g_autofree gchar *legacy_name = entry_name_for_stage(context->stage, context->entry_name);
    secret_password_lookup(schema_for_stage(context->stage), NULL, on_password_lookup,
                           context, "name", legacy_name, NULL);
    return;
  } else if (password == NULL) {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(fl_value_new_null()));
  } else {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(fl_value_new_string(password)));
    secret_password_free(password);
  }
  fl_method_call_respond(context->method_call, response, nullptr);
  secret_lookup_context_free(context);
}

static void on_password_exists(GObject *source, GAsyncResult *result, gpointer user_data) {
  GError *error = NULL;
  SecretLookupContext *context = (SecretLookupContext *)user_data;
  g_autoptr(FlMethodResponse) response = nullptr;

  gchar *password = secret_password_lookup_finish(result, &error);

  if (error != NULL) {
    response = _handle_error("Failed to lookup secret", error);
    g_error_free(error);
  } else if (password == NULL && context->stage != kLookupStageLegacySchema) {
    context->stage = (LookupStage)(context->stage + 1);
    g_autofree gchar *legacy_name = entry_name_for_stage(context->stage, context->entry_name);
    secret_password_lookup(schema_for_stage(context->stage), NULL, on_password_exists,
                           context, "name", legacy_name, NULL);
    return;
  } else {
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(
        fl_value_new_bool(password != NULL)));
    if (password != NULL) {
      secret_password_free(password);
    }
  }
  fl_method_call_respond(context->method_call, response, nullptr);
  secret_lookup_context_free(context);
}

static void webauthn_secure_storage_plugin_handle_method_call(WebauthnSecureStoragePlugin *self, FlMethodCall *method_call) {
  g_autoptr(FlMethodResponse) response = nullptr;

  const gchar *method = fl_method_call_get_name(method_call);
  FlValue *args = fl_method_call_get_args(method_call);

  if (strcmp(method, "canAuthenticate") == 0) {
    FlValue* options = fl_value_lookup_string(args, "options");
    gboolean authentication_required = FALSE;
    if (options != NULL && fl_value_get_type(options) == FL_VALUE_TYPE_MAP) {
      FlValue* authRequired = fl_value_lookup_string(options, "authenticationRequired");
      authentication_required = authRequired != NULL && fl_value_get_bool(authRequired);
    }

    GError *error = NULL;
    FprintAvailability availability = get_fprint_availability(&error);
    if (error != NULL) {
      g_error_free(error);
    }

    const gchar *result_value = "ErrorHwUnavailable";
    switch (availability) {
      case kFprintAvailabilityAvailable:
        result_value = "Success";
        break;
      case kFprintAvailabilityNoEnrolled:
        result_value = "ErrorNoBiometricEnrolled";
        break;
      case kFprintAvailabilityNoDevice:
        result_value = authentication_required ? "ErrorUnknown" : "ErrorNoHardware";
        break;
      case kFprintAvailabilityUnavailable:
      default:
        result_value = authentication_required ? "ErrorUnknown" : "ErrorHwUnavailable";
        break;
    }
    g_autoptr(FlValue) result = fl_value_new_string(result_value);
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(result));
  } else if (strcmp(method, kMethodGetPasskeyAvailability) == 0) {
    response = handle_get_passkey_availability();
  } else if (strcmp(method, kMethodRegisterPasskey) == 0) {
    response = handle_register_passkey(args);
  } else if (strcmp(method, kMethodAuthenticateWithPasskey) == 0) {
    response = handle_authenticate_with_passkey(args);
  } else if (strcmp(method, "init") == 0) {
    response = handleInit(self, args);
  } else if (IS_METHOD(method, kMethodWrite)) {
    const gchar *entry_name = fl_value_get_string(fl_value_lookup_string(args, "name"));
    response = biometric_response_if_needed(self, method_call, args, entry_name);
    if (response != NULL) {
      fl_method_call_respond(method_call, response, nullptr);
      return;
    }
    METHOD_PARAM_NAME(name, kNamePrefix, args);
    const gchar *content = fl_value_get_string(fl_value_lookup_string(args, "content"));
    g_object_ref(method_call);
    secret_password_store(BIOMETRIC_SCHEMA, SECRET_COLLECTION_DEFAULT, name,
                          content, NULL, on_password_stored, method_call,
                          "name", name, NULL);
    return;
  } else if (IS_METHOD(method, kMethodRead)) {
    const gchar *entry_name = fl_value_get_string(fl_value_lookup_string(args, "name"));
    response = biometric_response_if_needed(self, method_call, args, entry_name);
    if (response != NULL) {
      fl_method_call_respond(method_call, response, nullptr);
      return;
    }
    METHOD_PARAM_NAME(name, kNamePrefix, args);
    SecretLookupContext *context = secret_lookup_context_new(method_call, entry_name);
    secret_password_lookup(BIOMETRIC_SCHEMA, NULL, on_password_lookup,
                           context, "name", name, NULL);
    return;
  } else if (IS_METHOD(method, kMethodExists)) {
    const gchar *entry_name = fl_value_get_string(fl_value_lookup_string(args, "name"));
    METHOD_PARAM_NAME(name, kNamePrefix, args);
    SecretLookupContext *context = secret_lookup_context_new(method_call, entry_name);
    secret_password_lookup(BIOMETRIC_SCHEMA, NULL, on_password_exists,
                           context, "name", name, NULL);
    return;
  } else if (IS_METHOD(method, kMethodDelete)) {
    const gchar *entry_name = fl_value_get_string(fl_value_lookup_string(args, "name"));
    METHOD_PARAM_NAME(name, kNamePrefix, args);
    SecretDeleteContext *context = secret_delete_context_new(method_call, entry_name);
    secret_password_clear(BIOMETRIC_SCHEMA, NULL, on_password_cleared,
                          context, "name", name, NULL);
    return;
  } else {
    response = FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());
  }

  fl_method_call_respond(method_call, response, nullptr);
}

static void webauthn_secure_storage_plugin_dispose(GObject* object) {
  WebauthnSecureStoragePlugin* self = WEBAUTHN_SECURE_STORAGE_PLUGIN(object);
  g_clear_pointer(&self->storage_authentication_required, g_hash_table_unref);
  G_OBJECT_CLASS(webauthn_secure_storage_plugin_parent_class)->dispose(object);
}

static void webauthn_secure_storage_plugin_class_init(WebauthnSecureStoragePluginClass* klass) {
  G_OBJECT_CLASS(klass)->dispose = webauthn_secure_storage_plugin_dispose;
}

static void webauthn_secure_storage_plugin_init(WebauthnSecureStoragePlugin* self) {
  fido_init(0);
  self->storage_authentication_required = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
}

static void method_call_cb(FlMethodChannel* channel, FlMethodCall* method_call, gpointer user_data) {
  WebauthnSecureStoragePlugin* plugin = WEBAUTHN_SECURE_STORAGE_PLUGIN(user_data);
  webauthn_secure_storage_plugin_handle_method_call(plugin, method_call);
}

void webauthn_secure_storage_plugin_register_with_registrar(FlPluginRegistrar* registrar) {
  WebauthnSecureStoragePlugin* plugin = WEBAUTHN_SECURE_STORAGE_PLUGIN(
      g_object_new(webauthn_secure_storage_plugin_get_type(), nullptr));

  g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
  g_autoptr(FlMethodChannel) channel =
      fl_method_channel_new(fl_plugin_registrar_get_messenger(registrar),
                "webauthn_secure_storage",
                            FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(channel, method_call_cb,
                                            g_object_ref(plugin),
                                            g_object_unref);

  g_object_unref(plugin);
}
