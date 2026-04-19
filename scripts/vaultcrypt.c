#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <CommonCrypto/CommonRandom.h>
#include <CommonCrypto/CommonSymmetricKeywrap.h>
#include <errno.h>
#include <fcntl.h>
#include <readpassphrase.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * vaultcrypt
 *
 * Current default format (v3):
 *   passphrase -> PBKDF2 passphrase KEK -> wrapped random per-file key
 *   recovery key -> recovery KEK -> same wrapped random per-file key
 *   per-file key -> chunked AES-256-CTR + per-chunk HMAC-SHA256
 *
 * Legacy format (v1), still supported for decryption/info:
 *   passphrase -> PBKDF2 -> direct data encryption/authentication keys
 *
 * v3 layout (all integers big-endian):
 *   magic[8]              = "VLTENC03"
 *   version[4]            = 3
 *   kdf_id[4]             = 1   (PBKDF2-HMAC-SHA256)
 *   cipher_id[4]          = 1   (AES-256-CTR payload)
 *   mac_id[4]             = 2   (chunked HMAC-SHA256)
 *   wrap_id[4]            = 1   (AES Key Wrap, RFC 3394)
 *   iterations[4]         = PBKDF2 iteration count
 *   salt_len[4]           = 32
 *   iv_len[4]             = 16
 *   key_slots_count[4]
 *   chunk_size[4]
 *   salt[32]
 *   iv[16]                = random stream nonce prefix
 *   repeated key slots:
 *     slot_type[4]        = 1   (passphrase slot)
 *                           2   (recovery slot)
 *     wrapped_key_len[4]
 *     wrapped_key[n]
 *   header_tag[32]        = HMAC-SHA256("VLT3HDR" || header || slots)
 *   repeated chunks:
 *     chunk_len[4]
 *     chunk_flags[4]      = bit0 => final chunk
 *     ciphertext[chunk_len]
 *     chunk_tag[32]       = HMAC-SHA256("VLT3CHK" || iv || chunk_index || flags || len || ciphertext)
 *
 * Each wrapped key currently contains a 64-byte random file key:
 *   first 32 bytes  = AES-256-CTR key
 *   last 32 bytes   = HMAC-SHA256 key
 *
 * v1/v2 remain supported for backward-compatible decrypt/info/rewrap.
 */

#define MAGIC_V1 "VLTENC01"
#define MAGIC_V2 "VLTENC02"
#define MAGIC_V3 "VLTENC03"
#define MAGIC_LEN 8

#define VERSION_V1 1u
#define VERSION_V2 2u
#define VERSION_V3 3u

#define KDF_ID_PBKDF2_SHA256 1u
#define CIPHER_ID_AES256_CTR 1u
#define MAC_ID_HMAC_SHA256 1u
#define MAC_ID_HMAC_SHA256_STREAM 2u
#define WRAP_ID_AES_KEY_WRAP 1u

#define SLOT_TYPE_PASSPHRASE 1u
#define SLOT_TYPE_RECOVERY 2u

#define SALT_LEN 32u
#define IV_LEN 16u
#define MASTER_KEY_LEN 32u
#define RECOVERY_KEY_LEN 32u
#define PAYLOAD_ENC_KEY_LEN 32u
#define PAYLOAD_MAC_KEY_LEN 32u
#define FILE_KEY_LEN (PAYLOAD_ENC_KEY_LEN + PAYLOAD_MAC_KEY_LEN)
#define LEGACY_DERIVED_KEY_LEN 64u
#define TAG_LEN 32u
#define V1_HEADER_LEN (MAGIC_LEN + (7u * 4u) + SALT_LEN + IV_LEN)
#define V2_FIXED_HEADER_LEN (MAGIC_LEN + (9u * 4u) + SALT_LEN + IV_LEN)
#define V3_FIXED_HEADER_LEN (MAGIC_LEN + (10u * 4u) + SALT_LEN + IV_LEN)
#define V2_SLOT_HEADER_LEN (2u * 4u)
#define DEFAULT_ITERATIONS 600000u
#define MIN_ITERATIONS 100000u
#define MAX_KEY_SLOTS 8u
#define MAX_WRAPPED_KEY_LEN 256u
#define CHUNK_SIZE 65536u
#define STREAM_CHUNK_SIZE (1024u * 1024u)
#define V3_CHUNK_META_LEN 8u
#define V3_CHUNK_FINAL_FLAG 1u
#define PASS_MAX 1024u
#define MAX_RECOVERY_PATH 4096u
#define RECOVERY_KEY_FILE_MAGIC "VLTREC01"
#define RECOVERY_KEY_FILE_LEN (8u + (RECOVERY_KEY_LEN * 2u) + 1u)

typedef enum {
  FORMAT_UNKNOWN = 0,
  FORMAT_V1 = 1,
  FORMAT_V2 = 2,
  FORMAT_V3 = 3
} VaultFormat;

typedef struct {
  int force;
  int allow_stdout;
  int require_tty;
  int info_json;
  const char *recovery_key_path;
  const char *recovery_key_out_path;
} Options;

typedef struct {
  uint32_t version;
  uint32_t kdf_id;
  uint32_t cipher_id;
  uint32_t mac_id;
  uint32_t iterations;
  uint32_t salt_len;
  uint32_t iv_len;
  uint8_t salt[SALT_LEN];
  uint8_t iv[IV_LEN];
} VaultHeaderV1;

typedef struct {
  uint32_t version;
  uint32_t kdf_id;
  uint32_t cipher_id;
  uint32_t mac_id;
  uint32_t wrap_id;
  uint32_t iterations;
  uint32_t salt_len;
  uint32_t iv_len;
  uint32_t slot_count;
  uint8_t salt[SALT_LEN];
  uint8_t iv[IV_LEN];
} VaultHeaderV2;

typedef struct {
  uint32_t version;
  uint32_t kdf_id;
  uint32_t cipher_id;
  uint32_t mac_id;
  uint32_t wrap_id;
  uint32_t iterations;
  uint32_t salt_len;
  uint32_t iv_len;
  uint32_t slot_count;
  uint32_t chunk_size;
  uint8_t salt[SALT_LEN];
  uint8_t iv[IV_LEN];
} VaultHeaderV3;

typedef struct {
  uint32_t type;
  uint32_t wrapped_key_len;
  uint8_t header_bytes[V2_SLOT_HEADER_LEN];
  uint8_t wrapped_key[MAX_WRAPPED_KEY_LEN];
} VaultKeySlotV2;

static FILE *open_input_file(const char *path);
static void finalize_output_file(FILE *fp, const char *temp_path, const char *final_path);
static FILE *open_output_file_strict(const char *path, int force, char **temp_path_out);

static void secure_bzero(void *ptr, size_t len) {
  volatile unsigned char *p = (volatile unsigned char *)ptr;
  while (len-- > 0) {
    *p++ = 0;
  }
}

static void usage(FILE *stream, int exit_code) {
  fprintf(stream,
          "Usage:\n"
          "  vaultcrypt enc -i INPUT [-o OUTPUT] [-n ITERATIONS] [-f]\n"
          "                 [--recovery-key-out PATH]\n"
          "  vaultcrypt dec -i INPUT [-o OUTPUT|-] [-f] [--stdout] [--recovery-key PATH]\n"
          "  vaultcrypt rewrap -i INPUT [-o OUTPUT] [-n ITERATIONS] [-f]\n"
          "                    [--recovery-key PATH] [--recovery-key-out PATH]\n"
          "  vaultcrypt info -i INPUT [--json]\n"
          "  vaultcrypt selftest\n"
          "\n"
          "Notes:\n"
          "  - macOS only: uses built-in CommonCrypto.\n"
          "  - enc writes VLTENC03 streamed envelope files.\n"
          "  - dec/info support VLTENC01, VLTENC02, and VLTENC03.\n"
          "  - passphrase and recovery slots can unlock the same file key.\n"
          "  - VLTENC03 decrypts chunk-by-chunk without a scratch plaintext file.\n"
          "  - rewrap rotates passphrase access and can preserve or rotate recovery access.\n"
          "  - enc prompts twice for a passphrase.\n"
          "  - dec verifies each chunk before releasing that chunk's plaintext.\n"
          "  - --recovery-key PATH unlocks via an independent recovery key file.\n"
          "  - --recovery-key-out PATH generates a new recovery key file and slot.\n"
          "  - enc OUTPUT defaults to INPUT.vlt.\n"
          "  - rewrap OUTPUT defaults to INPUT (in place).\n"
          "  - dec requires -o PATH or explicit stdout with -o - or --stdout.\n");
  exit(exit_code);
}

static void fail_errno(const char *msg) {
  fprintf(stderr, "vaultcrypt: %s: %s\n", msg, strerror(errno));
  exit(1);
}

static void fail_msg(const char *msg) {
  fprintf(stderr, "vaultcrypt: %s\n", msg);
  exit(1);
}

static void write_be32(uint8_t *dst, uint32_t value) {
  dst[0] = (uint8_t)(value >> 24);
  dst[1] = (uint8_t)(value >> 16);
  dst[2] = (uint8_t)(value >> 8);
  dst[3] = (uint8_t)value;
}

static uint32_t read_be32(const uint8_t *src) {
  return ((uint32_t)src[0] << 24) |
         ((uint32_t)src[1] << 16) |
         ((uint32_t)src[2] << 8) |
         (uint32_t)src[3];
}

static bool constant_time_eq(const uint8_t *a, const uint8_t *b, size_t len) {
  uint8_t diff = 0;
  size_t i;

  for (i = 0; i < len; ++i) {
    diff |= (uint8_t)(a[i] ^ b[i]);
  }
  return diff == 0;
}

static void read_exact(FILE *fp, void *buf, size_t len, const char *what) {
  if (fread(buf, 1, len, fp) != len) {
    if (ferror(fp)) {
      fail_errno(what);
    }
    fail_msg("unexpected end of file");
  }
}

static void write_exact(FILE *fp, const void *buf, size_t len, const char *what) {
  if (fwrite(buf, 1, len, fp) != len) {
    fail_errno(what);
  }
}

static void fsync_file(FILE *fp, const char *label) {
  if (fflush(fp) != 0) {
    fail_errno(label);
  }
  if (fsync(fileno(fp)) != 0) {
    fail_errno(label);
  }
}

static char *xstrdup(const char *src) {
  size_t len = strlen(src);
  char *dst = (char *)malloc(len + 1);

  if (dst == NULL) {
    fail_msg("out of memory");
  }

  memcpy(dst, src, len + 1);
  return dst;
}

static void lock_memory_best_effort(void *ptr, size_t len) {
  if (ptr == NULL || len == 0) {
    return;
  }
  (void)mlock(ptr, len);
}

static void unlock_memory_best_effort(void *ptr, size_t len) {
  if (ptr == NULL || len == 0) {
    return;
  }
  (void)munlock(ptr, len);
}

static void secure_release_buffer(void *ptr, size_t len) {
  if (ptr == NULL) {
    return;
  }
  secure_bzero(ptr, len);
  unlock_memory_best_effort(ptr, len);
}

static void secure_free_string(char **value) {
  size_t len;

  if (value == NULL || *value == NULL) {
    return;
  }

  len = strlen(*value) + 1;
  secure_release_buffer(*value, len);
  free(*value);
  *value = NULL;
}

static char hex_digit(unsigned int value) {
  return (char)(value < 10u ? ('0' + value) : ('a' + (value - 10u)));
}

static int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return 10 + (c - 'a');
  }
  if (c >= 'A' && c <= 'F') {
    return 10 + (c - 'A');
  }
  return -1;
}

static void hex_encode(const uint8_t *src, size_t len, char *dst) {
  size_t i;

  for (i = 0; i < len; ++i) {
    dst[i * 2] = hex_digit((unsigned int)(src[i] >> 4));
    dst[(i * 2) + 1] = hex_digit((unsigned int)(src[i] & 0x0fu));
  }
  dst[len * 2] = '\0';
}

static void hex_decode_exact(const char *src, size_t hex_len, uint8_t *dst, size_t dst_len) {
  size_t i;

  if (hex_len != dst_len * 2u) {
    fail_msg("invalid recovery key length");
  }

  for (i = 0; i < dst_len; ++i) {
    int hi = hex_value(src[i * 2]);
    int lo = hex_value(src[(i * 2) + 1]);

    if (hi < 0 || lo < 0) {
      fail_msg("recovery key file contains non-hex characters");
    }
    dst[i] = (uint8_t)((hi << 4) | lo);
  }
}

static void write_recovery_key_file(const char *path,
                                    const uint8_t recovery_key[RECOVERY_KEY_LEN]) {
  FILE *fp;
  char *temp_path = NULL;
  char hex[(RECOVERY_KEY_LEN * 2u) + 1u];

  if (path == NULL) {
    return;
  }
  if (strlen(path) >= MAX_RECOVERY_PATH) {
    fail_msg("recovery key path is too long");
  }

  hex_encode(recovery_key, RECOVERY_KEY_LEN, hex);
  fp = open_output_file_strict(path, 1, &temp_path);
  fprintf(fp, "%s%s\n", RECOVERY_KEY_FILE_MAGIC, hex);
  finalize_output_file(fp, temp_path, path);
  secure_bzero(hex, sizeof(hex));
}

static void read_recovery_key_file(const char *path,
                                   uint8_t recovery_key[RECOVERY_KEY_LEN]) {
  FILE *fp;
  char buf[RECOVERY_KEY_FILE_LEN + 16u];
  size_t nread;
  char *newline;

  if (path == NULL) {
    fail_msg("a recovery key file path is required");
  }

  fp = open_input_file(path);
  nread = fread(buf, 1, sizeof(buf) - 1u, fp);
  if (ferror(fp)) {
    fclose(fp);
    fail_errno("read recovery key file");
  }
  fclose(fp);
  buf[nread] = '\0';

  newline = strpbrk(buf, "\r\n");
  if (newline != NULL) {
    *newline = '\0';
  }

  if (strncmp(buf, RECOVERY_KEY_FILE_MAGIC, 8) != 0) {
    fail_msg("recovery key file has an unsupported format");
  }

  hex_decode_exact(buf + 8, strlen(buf + 8), recovery_key, RECOVERY_KEY_LEN);
  secure_bzero(buf, sizeof(buf));
}

static char *default_encrypt_output(const char *input) {
  const char *suffix = ".vlt";
  size_t len = strlen(input) + strlen(suffix) + 1;
  char *path = (char *)malloc(len);

  if (path == NULL) {
    fail_msg("out of memory");
  }

  snprintf(path, len, "%s%s", input, suffix);
  return path;
}

static char *make_temp_pattern(const char *output) {
  const char *suffix = ".tmp.XXXXXX";
  size_t len = strlen(output) + strlen(suffix) + 1;
  char *pattern = (char *)malloc(len);

  if (pattern == NULL) {
    fail_msg("out of memory");
  }

  snprintf(pattern, len, "%s%s", output, suffix);
  return pattern;
}

static FILE *open_output_temp(const char *output, char **temp_path_out, int force) {
  char *pattern;
  int fd;
  FILE *fp;

  if (!force && access(output, F_OK) == 0) {
    fail_msg("refusing to overwrite existing output file; use -f to override");
  }

  pattern = make_temp_pattern(output);
  fd = mkstemp(pattern);
  if (fd < 0) {
    free(pattern);
    fail_errno("mkstemp");
  }

  if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
    close(fd);
    unlink(pattern);
    free(pattern);
    fail_errno("fchmod");
  }

  fp = fdopen(fd, "w+b");
  if (fp == NULL) {
    close(fd);
    unlink(pattern);
    free(pattern);
    fail_errno("fdopen");
  }

  *temp_path_out = pattern;
  return fp;
}

static FILE *open_input_file(const char *path) {
  FILE *fp = fopen(path, "rb");
  if (fp == NULL) {
    fail_errno(path);
  }
  return fp;
}

static uint64_t input_file_size(const char *path) {
  struct stat st;

  if (stat(path, &st) != 0) {
    fail_errno(path);
  }
  if (!S_ISREG(st.st_mode)) {
    fail_msg("input must be a regular file");
  }
  if (st.st_size < 0) {
    fail_msg("input size is invalid");
  }
  return (uint64_t)st.st_size;
}

static void random_bytes(void *buf, size_t len) {
  if (CCRandomGenerateBytes(buf, len) != kCCSuccess) {
    fail_msg("failed to obtain cryptographic randomness");
  }
}

static void derive_key_material(const char *passphrase,
                                const uint8_t salt[SALT_LEN],
                                uint32_t iterations,
                                uint8_t *out,
                                size_t out_len) {
  int rc;

  rc = CCKeyDerivationPBKDF(kCCPBKDF2,
                            passphrase,
                            strlen(passphrase),
                            salt,
                            SALT_LEN,
                            kCCPRFHmacAlgSHA256,
                            iterations,
                            out,
                            out_len);
  if (rc != kCCSuccess) {
    fail_msg("key derivation failed");
  }
}

static void derive_legacy_keys(const char *passphrase,
                               const uint8_t salt[SALT_LEN],
                               uint32_t iterations,
                               uint8_t enc_key[PAYLOAD_ENC_KEY_LEN],
                               uint8_t mac_key[PAYLOAD_MAC_KEY_LEN]) {
  uint8_t derived[LEGACY_DERIVED_KEY_LEN];

  derive_key_material(passphrase, salt, iterations, derived, sizeof(derived));
  memcpy(enc_key, derived, PAYLOAD_ENC_KEY_LEN);
  memcpy(mac_key, derived + PAYLOAD_ENC_KEY_LEN, PAYLOAD_MAC_KEY_LEN);
  secure_bzero(derived, sizeof(derived));
}

static void derive_master_key(const char *passphrase,
                              const uint8_t salt[SALT_LEN],
                              uint32_t iterations,
                              uint8_t master_key[MASTER_KEY_LEN]) {
  derive_key_material(passphrase, salt, iterations, master_key, MASTER_KEY_LEN);
}

static void fill_header_v1(VaultHeaderV1 *hdr, uint32_t iterations) {
  hdr->version = VERSION_V1;
  hdr->kdf_id = KDF_ID_PBKDF2_SHA256;
  hdr->cipher_id = CIPHER_ID_AES256_CTR;
  hdr->mac_id = MAC_ID_HMAC_SHA256;
  hdr->iterations = iterations;
  hdr->salt_len = SALT_LEN;
  hdr->iv_len = IV_LEN;
  random_bytes(hdr->salt, sizeof(hdr->salt));
  random_bytes(hdr->iv, sizeof(hdr->iv));
}

static void fill_header_v2(VaultHeaderV2 *hdr, uint32_t iterations) {
  hdr->version = VERSION_V2;
  hdr->kdf_id = KDF_ID_PBKDF2_SHA256;
  hdr->cipher_id = CIPHER_ID_AES256_CTR;
  hdr->mac_id = MAC_ID_HMAC_SHA256;
  hdr->wrap_id = WRAP_ID_AES_KEY_WRAP;
  hdr->iterations = iterations;
  hdr->salt_len = SALT_LEN;
  hdr->iv_len = IV_LEN;
  hdr->slot_count = 0u;
  random_bytes(hdr->salt, sizeof(hdr->salt));
  random_bytes(hdr->iv, sizeof(hdr->iv));
}

static void fill_header_v3(VaultHeaderV3 *hdr, uint32_t iterations) {
  hdr->version = VERSION_V3;
  hdr->kdf_id = KDF_ID_PBKDF2_SHA256;
  hdr->cipher_id = CIPHER_ID_AES256_CTR;
  hdr->mac_id = MAC_ID_HMAC_SHA256_STREAM;
  hdr->wrap_id = WRAP_ID_AES_KEY_WRAP;
  hdr->iterations = iterations;
  hdr->salt_len = SALT_LEN;
  hdr->iv_len = IV_LEN;
  hdr->slot_count = 0u;
  hdr->chunk_size = STREAM_CHUNK_SIZE;
  random_bytes(hdr->salt, sizeof(hdr->salt));
  random_bytes(hdr->iv, sizeof(hdr->iv));
}

static void serialize_header_v1(const VaultHeaderV1 *hdr, uint8_t out[V1_HEADER_LEN]) {
  memcpy(out, MAGIC_V1, MAGIC_LEN);
  write_be32(out + 8, hdr->version);
  write_be32(out + 12, hdr->kdf_id);
  write_be32(out + 16, hdr->cipher_id);
  write_be32(out + 20, hdr->mac_id);
  write_be32(out + 24, hdr->iterations);
  write_be32(out + 28, hdr->salt_len);
  write_be32(out + 32, hdr->iv_len);
  memcpy(out + 36, hdr->salt, SALT_LEN);
  memcpy(out + 68, hdr->iv, IV_LEN);
}

static void serialize_header_v2(const VaultHeaderV2 *hdr, uint8_t out[V2_FIXED_HEADER_LEN]) {
  memcpy(out, MAGIC_V2, MAGIC_LEN);
  write_be32(out + 8, hdr->version);
  write_be32(out + 12, hdr->kdf_id);
  write_be32(out + 16, hdr->cipher_id);
  write_be32(out + 20, hdr->mac_id);
  write_be32(out + 24, hdr->wrap_id);
  write_be32(out + 28, hdr->iterations);
  write_be32(out + 32, hdr->salt_len);
  write_be32(out + 36, hdr->iv_len);
  write_be32(out + 40, hdr->slot_count);
  memcpy(out + 44, hdr->salt, SALT_LEN);
  memcpy(out + 76, hdr->iv, IV_LEN);
}

static void serialize_header_v3(const VaultHeaderV3 *hdr, uint8_t out[V3_FIXED_HEADER_LEN]) {
  memcpy(out, MAGIC_V3, MAGIC_LEN);
  write_be32(out + 8, hdr->version);
  write_be32(out + 12, hdr->kdf_id);
  write_be32(out + 16, hdr->cipher_id);
  write_be32(out + 20, hdr->mac_id);
  write_be32(out + 24, hdr->wrap_id);
  write_be32(out + 28, hdr->iterations);
  write_be32(out + 32, hdr->salt_len);
  write_be32(out + 36, hdr->iv_len);
  write_be32(out + 40, hdr->slot_count);
  write_be32(out + 44, hdr->chunk_size);
  memcpy(out + 48, hdr->salt, SALT_LEN);
  memcpy(out + 80, hdr->iv, IV_LEN);
}

static VaultFormat detect_format(const uint8_t magic[MAGIC_LEN]) {
  if (memcmp(magic, MAGIC_V1, MAGIC_LEN) == 0) {
    return FORMAT_V1;
  }
  if (memcmp(magic, MAGIC_V2, MAGIC_LEN) == 0) {
    return FORMAT_V2;
  }
  if (memcmp(magic, MAGIC_V3, MAGIC_LEN) == 0) {
    return FORMAT_V3;
  }
  return FORMAT_UNKNOWN;
}

static void parse_header_v1(const uint8_t in[V1_HEADER_LEN], VaultHeaderV1 *hdr) {
  if (detect_format(in) != FORMAT_V1) {
    fail_msg("file does not start with a VLTENC01 header");
  }

  hdr->version = read_be32(in + 8);
  hdr->kdf_id = read_be32(in + 12);
  hdr->cipher_id = read_be32(in + 16);
  hdr->mac_id = read_be32(in + 20);
  hdr->iterations = read_be32(in + 24);
  hdr->salt_len = read_be32(in + 28);
  hdr->iv_len = read_be32(in + 32);
  memcpy(hdr->salt, in + 36, SALT_LEN);
  memcpy(hdr->iv, in + 68, IV_LEN);

  if (hdr->version != VERSION_V1 ||
      hdr->kdf_id != KDF_ID_PBKDF2_SHA256 ||
      hdr->cipher_id != CIPHER_ID_AES256_CTR ||
      hdr->mac_id != MAC_ID_HMAC_SHA256) {
    fail_msg("unsupported VLTENC01 parameters");
  }
  if (hdr->salt_len != SALT_LEN || hdr->iv_len != IV_LEN) {
    fail_msg("unsupported salt or IV size in VLTENC01 header");
  }
  if (hdr->iterations < MIN_ITERATIONS) {
    fail_msg("stored PBKDF2 iteration count is below the supported minimum");
  }
}

static void parse_header_v2(const uint8_t in[V2_FIXED_HEADER_LEN], VaultHeaderV2 *hdr) {
  if (detect_format(in) != FORMAT_V2) {
    fail_msg("file does not start with a VLTENC02 header");
  }

  hdr->version = read_be32(in + 8);
  hdr->kdf_id = read_be32(in + 12);
  hdr->cipher_id = read_be32(in + 16);
  hdr->mac_id = read_be32(in + 20);
  hdr->wrap_id = read_be32(in + 24);
  hdr->iterations = read_be32(in + 28);
  hdr->salt_len = read_be32(in + 32);
  hdr->iv_len = read_be32(in + 36);
  hdr->slot_count = read_be32(in + 40);
  memcpy(hdr->salt, in + 44, SALT_LEN);
  memcpy(hdr->iv, in + 76, IV_LEN);

  if (hdr->version != VERSION_V2 ||
      hdr->kdf_id != KDF_ID_PBKDF2_SHA256 ||
      hdr->cipher_id != CIPHER_ID_AES256_CTR ||
      hdr->mac_id != MAC_ID_HMAC_SHA256 ||
      hdr->wrap_id != WRAP_ID_AES_KEY_WRAP) {
    fail_msg("unsupported VLTENC02 parameters");
  }
  if (hdr->salt_len != SALT_LEN || hdr->iv_len != IV_LEN) {
    fail_msg("unsupported salt or IV size in VLTENC02 header");
  }
  if (hdr->iterations < MIN_ITERATIONS) {
    fail_msg("stored PBKDF2 iteration count is below the supported minimum");
  }
  if (hdr->slot_count == 0 || hdr->slot_count > MAX_KEY_SLOTS) {
    fail_msg("unsupported VLTENC02 key slot count");
  }
}

static void parse_header_v3(const uint8_t in[V3_FIXED_HEADER_LEN], VaultHeaderV3 *hdr) {
  if (detect_format(in) != FORMAT_V3) {
    fail_msg("file does not start with a VLTENC03 header");
  }

  hdr->version = read_be32(in + 8);
  hdr->kdf_id = read_be32(in + 12);
  hdr->cipher_id = read_be32(in + 16);
  hdr->mac_id = read_be32(in + 20);
  hdr->wrap_id = read_be32(in + 24);
  hdr->iterations = read_be32(in + 28);
  hdr->salt_len = read_be32(in + 32);
  hdr->iv_len = read_be32(in + 36);
  hdr->slot_count = read_be32(in + 40);
  hdr->chunk_size = read_be32(in + 44);
  memcpy(hdr->salt, in + 48, SALT_LEN);
  memcpy(hdr->iv, in + 80, IV_LEN);

  if (hdr->version != VERSION_V3 ||
      hdr->kdf_id != KDF_ID_PBKDF2_SHA256 ||
      hdr->cipher_id != CIPHER_ID_AES256_CTR ||
      hdr->mac_id != MAC_ID_HMAC_SHA256_STREAM ||
      hdr->wrap_id != WRAP_ID_AES_KEY_WRAP) {
    fail_msg("unsupported VLTENC03 parameters");
  }
  if (hdr->salt_len != SALT_LEN || hdr->iv_len != IV_LEN) {
    fail_msg("unsupported salt or IV size in VLTENC03 header");
  }
  if (hdr->iterations < MIN_ITERATIONS) {
    fail_msg("stored PBKDF2 iteration count is below the supported minimum");
  }
  if (hdr->slot_count == 0 || hdr->slot_count > MAX_KEY_SLOTS) {
    fail_msg("unsupported VLTENC03 key slot count");
  }
  if (hdr->chunk_size == 0u || hdr->chunk_size > (64u * 1024u * 1024u)) {
    fail_msg("unsupported VLTENC03 chunk size");
  }
}

static void serialize_slot_v2(VaultKeySlotV2 *slot) {
  write_be32(slot->header_bytes + 0, slot->type);
  write_be32(slot->header_bytes + 4, slot->wrapped_key_len);
}

static void parse_slot_v2(const uint8_t in[V2_SLOT_HEADER_LEN], VaultKeySlotV2 *slot) {
  slot->type = read_be32(in + 0);
  slot->wrapped_key_len = read_be32(in + 4);
  memcpy(slot->header_bytes, in, V2_SLOT_HEADER_LEN);

  if (slot->wrapped_key_len == 0 || slot->wrapped_key_len > MAX_WRAPPED_KEY_LEN) {
    fail_msg("unsupported wrapped key length");
  }
  if ((slot->wrapped_key_len % 8u) != 0) {
    fail_msg("wrapped key length must be a multiple of 8");
  }
}

static void set_slot_count(VaultHeaderV2 *hdr, uint32_t slot_count) {
  if (slot_count == 0 || slot_count > MAX_KEY_SLOTS) {
    fail_msg("invalid slot count");
  }
  hdr->slot_count = slot_count;
}

static void set_slot_count_v3(VaultHeaderV3 *hdr, uint32_t slot_count) {
  if (slot_count == 0 || slot_count > MAX_KEY_SLOTS) {
    fail_msg("invalid slot count");
  }
  hdr->slot_count = slot_count;
}

static char *prompt_passphrase(const char *prompt, int confirm, int require_tty) {
  char first[PASS_MAX];
  char second[PASS_MAX];
  char *result = NULL;
  int flags = require_tty ? RPP_REQUIRE_TTY : RPP_STDIN;

  memset(first, 0, sizeof(first));
  memset(second, 0, sizeof(second));
  lock_memory_best_effort(first, sizeof(first));
  lock_memory_best_effort(second, sizeof(second));

  if (readpassphrase(prompt, first, sizeof(first), flags) == NULL) {
    fail_errno("readpassphrase");
  }
  if (first[0] == '\0') {
    secure_release_buffer(first, sizeof(first));
    secure_release_buffer(second, sizeof(second));
    fail_msg("empty passphrases are not allowed");
  }

  if (confirm) {
    if (readpassphrase("Confirm passphrase: ", second, sizeof(second), flags) == NULL) {
      secure_release_buffer(first, sizeof(first));
      secure_release_buffer(second, sizeof(second));
      fail_errno("readpassphrase");
    }
    if (strcmp(first, second) != 0) {
      secure_release_buffer(first, sizeof(first));
      secure_release_buffer(second, sizeof(second));
      fail_msg("passphrases did not match");
    }
  }

  result = xstrdup(first);
  lock_memory_best_effort(result, strlen(result) + 1);
  secure_release_buffer(first, sizeof(first));
  secure_release_buffer(second, sizeof(second));
  return result;
}

static CCCryptorRef create_ctr_cryptor(CCOperation op,
                                       const uint8_t key[PAYLOAD_ENC_KEY_LEN],
                                       const uint8_t iv[IV_LEN]) {
  CCCryptorRef cryptor = NULL;
  CCCryptorStatus status;

  status = CCCryptorCreateWithMode(op,
                                   kCCModeCTR,
                                   kCCAlgorithmAES,
                                   ccNoPadding,
                                   iv,
                                   key,
                                   PAYLOAD_ENC_KEY_LEN,
                                   NULL,
                                   0,
                                   0,
                                   kCCModeOptionCTR_BE,
                                   &cryptor);
  if (status != kCCSuccess) {
    fail_msg("failed to create AES-CTR context");
  }
  return cryptor;
}

static void finalize_output_file(FILE *fp, const char *temp_path, const char *final_path) {
  fsync_file(fp, "sync output");
  if (fclose(fp) != 0) {
    unlink(temp_path);
    fail_errno("fclose");
  }
  if (rename(temp_path, final_path) != 0) {
    unlink(temp_path);
    fail_errno("rename");
  }
}

static FILE *open_output_file_strict(const char *path, int force, char **temp_path_out) {
  if (path == NULL || strcmp(path, "-") == 0) {
    fail_msg("a regular file output path is required here");
  }
  return open_output_temp(path, temp_path_out, force);
}

static size_t expected_wrapped_file_key_len(void) {
  size_t len = CCSymmetricWrappedSize(kCCWRAPAES, FILE_KEY_LEN);
  if (len == 0 || len > MAX_WRAPPED_KEY_LEN) {
    fail_msg("invalid wrapped file key size");
  }
  return len;
}

static void wrap_file_key_for_slot(const uint8_t wrapping_key[MASTER_KEY_LEN],
                                   uint32_t slot_type,
                                   const uint8_t file_key[FILE_KEY_LEN],
                                   VaultKeySlotV2 *slot) {
  size_t wrapped_len = expected_wrapped_file_key_len();
  int rc;

  slot->type = slot_type;
  slot->wrapped_key_len = (uint32_t)wrapped_len;
  rc = CCSymmetricKeyWrap(kCCWRAPAES,
                          CCrfc3394_iv,
                          CCrfc3394_ivLen,
                          wrapping_key,
                          MASTER_KEY_LEN,
                          file_key,
                          FILE_KEY_LEN,
                          slot->wrapped_key,
                          &wrapped_len);
  if (rc != kCCSuccess) {
    fail_msg("failed to wrap file key");
  }

  slot->wrapped_key_len = (uint32_t)wrapped_len;
  serialize_slot_v2(slot);
}

static void unwrap_file_key_with_key(const uint8_t wrapping_key[MASTER_KEY_LEN],
                                     const VaultKeySlotV2 *slot,
                                     uint8_t file_key[FILE_KEY_LEN]) {
  size_t unwrapped_len = FILE_KEY_LEN;
  int rc;

  rc = CCSymmetricKeyUnwrap(kCCWRAPAES,
                            CCrfc3394_iv,
                            CCrfc3394_ivLen,
                            wrapping_key,
                            MASTER_KEY_LEN,
                            slot->wrapped_key,
                            slot->wrapped_key_len,
                            file_key,
                            &unwrapped_len);
  if (rc != kCCSuccess || unwrapped_len != FILE_KEY_LEN) {
    fail_msg("failed to unwrap file key: wrong key material or corrupted file");
  }
}

static void hmac_update_v2_slots(CCHmacContext *hmac,
                                 const VaultKeySlotV2 slots[MAX_KEY_SLOTS],
                                 uint32_t slot_count) {
  uint32_t i;

  for (i = 0; i < slot_count; ++i) {
    CCHmacUpdate(hmac, slots[i].header_bytes, sizeof(slots[i].header_bytes));
    CCHmacUpdate(hmac, slots[i].wrapped_key, slots[i].wrapped_key_len);
  }
}

static uint64_t read_slots(FILE *in,
                           uint32_t slot_count,
                           VaultKeySlotV2 slots[MAX_KEY_SLOTS]) {
  uint32_t i;
  uint8_t slot_header[V2_SLOT_HEADER_LEN];
  uint64_t total = 0;

  for (i = 0; i < slot_count; ++i) {
    read_exact(in, slot_header, sizeof(slot_header), "read key slot");
    parse_slot_v2(slot_header, &slots[i]);
    read_exact(in, slots[i].wrapped_key, slots[i].wrapped_key_len, "read wrapped key");
    total += (uint64_t)V2_SLOT_HEADER_LEN + (uint64_t)slots[i].wrapped_key_len;
  }

  return total;
}

static const VaultKeySlotV2 *find_slot_v2(const VaultKeySlotV2 slots[MAX_KEY_SLOTS],
                                          uint32_t slot_count,
                                          uint32_t type) {
  uint32_t i;

  for (i = 0; i < slot_count; ++i) {
    if (slots[i].type == type) {
      return &slots[i];
    }
  }

  return NULL;
}

static uint32_t slot_count_by_type(const VaultKeySlotV2 slots[MAX_KEY_SLOTS],
                                   uint32_t slot_count,
                                   uint32_t type) {
  uint32_t i;
  uint32_t count = 0;

  for (i = 0; i < slot_count; ++i) {
    if (slots[i].type == type) {
      count++;
    }
  }

  return count;
}

static void append_slot(VaultKeySlotV2 slots[MAX_KEY_SLOTS],
                        uint32_t *slot_count,
                        const VaultKeySlotV2 *slot) {
  if (*slot_count >= MAX_KEY_SLOTS) {
    fail_msg("too many key slots");
  }
  slots[*slot_count] = *slot;
  (*slot_count)++;
}

static void append_slots_except_type(VaultKeySlotV2 dst[MAX_KEY_SLOTS],
                                     uint32_t *dst_count,
                                     const VaultKeySlotV2 src[MAX_KEY_SLOTS],
                                     uint32_t src_count,
                                     uint32_t skip_type) {
  uint32_t i;

  for (i = 0; i < src_count; ++i) {
    if (src[i].type == skip_type) {
      continue;
    }
    append_slot(dst, dst_count, &src[i]);
  }
}

static void unwrap_file_key_from_slots(const uint8_t salt[SALT_LEN],
                                       uint32_t iterations,
                                       uint32_t slot_count,
                                       const VaultKeySlotV2 slots[MAX_KEY_SLOTS],
                                       const Options *opts,
                                       uint8_t file_key[FILE_KEY_LEN]) {
  uint8_t wrapping_key[MASTER_KEY_LEN];
  char *passphrase = NULL;
  const VaultKeySlotV2 *slot = NULL;

  memset(wrapping_key, 0, sizeof(wrapping_key));

  if (opts->recovery_key_path != NULL) {
    slot = find_slot_v2(slots, slot_count, SLOT_TYPE_RECOVERY);
    if (slot == NULL) {
      fail_msg("no recovery key slot found in file");
    }
    read_recovery_key_file(opts->recovery_key_path, wrapping_key);
  } else {
    slot = find_slot_v2(slots, slot_count, SLOT_TYPE_PASSPHRASE);
    if (slot == NULL) {
      fail_msg("no supported passphrase key slot found");
    }
    passphrase = prompt_passphrase("Passphrase: ", 0, opts->require_tty);
    derive_master_key(passphrase, salt, iterations, wrapping_key);
  }

  lock_memory_best_effort(wrapping_key, sizeof(wrapping_key));
  unwrap_file_key_with_key(wrapping_key, slot, file_key);
  secure_release_buffer(wrapping_key, sizeof(wrapping_key));
  secure_free_string(&passphrase);
}

static void write_be64(uint8_t *dst, uint64_t value) {
  dst[0] = (uint8_t)(value >> 56);
  dst[1] = (uint8_t)(value >> 48);
  dst[2] = (uint8_t)(value >> 40);
  dst[3] = (uint8_t)(value >> 32);
  dst[4] = (uint8_t)(value >> 24);
  dst[5] = (uint8_t)(value >> 16);
  dst[6] = (uint8_t)(value >> 8);
  dst[7] = (uint8_t)value;
}

static void derive_chunk_iv(const uint8_t base_iv[IV_LEN],
                            uint64_t chunk_index,
                            uint8_t chunk_iv[IV_LEN]) {
  memcpy(chunk_iv, base_iv, IV_LEN);
  write_be64(chunk_iv + (IV_LEN - 8u), chunk_index);
}

static void compute_v3_header_tag(const uint8_t mac_key[PAYLOAD_MAC_KEY_LEN],
                                  const uint8_t header_bytes[V3_FIXED_HEADER_LEN],
                                  const VaultKeySlotV2 slots[MAX_KEY_SLOTS],
                                  uint32_t slot_count,
                                  uint8_t tag[TAG_LEN]) {
  static const char domain[] = "VLT3HDR";
  CCHmacContext hmac;

  CCHmacInit(&hmac, kCCHmacAlgSHA256, mac_key, PAYLOAD_MAC_KEY_LEN);
  CCHmacUpdate(&hmac, domain, sizeof(domain) - 1u);
  CCHmacUpdate(&hmac, header_bytes, V3_FIXED_HEADER_LEN);
  hmac_update_v2_slots(&hmac, slots, slot_count);
  CCHmacFinal(&hmac, tag);
}

static void compute_v3_chunk_tag(const uint8_t mac_key[PAYLOAD_MAC_KEY_LEN],
                                 const uint8_t base_iv[IV_LEN],
                                 uint64_t chunk_index,
                                 uint32_t flags,
                                 const uint8_t *ciphertext,
                                 uint32_t chunk_len,
                                 uint8_t tag[TAG_LEN]) {
  static const char domain[] = "VLT3CHK";
  uint8_t idx_bytes[8];
  uint8_t len_bytes[4];
  uint8_t flags_bytes[4];
  CCHmacContext hmac;

  write_be64(idx_bytes, chunk_index);
  write_be32(len_bytes, chunk_len);
  write_be32(flags_bytes, flags);
  CCHmacInit(&hmac, kCCHmacAlgSHA256, mac_key, PAYLOAD_MAC_KEY_LEN);
  CCHmacUpdate(&hmac, domain, sizeof(domain) - 1u);
  CCHmacUpdate(&hmac, base_iv, IV_LEN);
  CCHmacUpdate(&hmac, idx_bytes, sizeof(idx_bytes));
  CCHmacUpdate(&hmac, flags_bytes, sizeof(flags_bytes));
  CCHmacUpdate(&hmac, len_bytes, sizeof(len_bytes));
  if (chunk_len > 0u) {
    CCHmacUpdate(&hmac, ciphertext, chunk_len);
  }
  CCHmacFinal(&hmac, tag);
}

static void print_recovery_lines_plain(uint32_t version, uint32_t recovery_slots) {
  printf("recovery:\n");
  if (version == VERSION_V1) {
    printf("  passphrase_only: yes\n");
    printf("  alternate_recovery_slot: no\n");
    printf("  method: derive keys from passphrase, then verify/decrypt the full file\n");
    return;
  }

  printf("  passphrase_only: %s\n", recovery_slots == 0u ? "yes" : "no");
  printf("  alternate_recovery_slot: %s\n", recovery_slots > 0u ? "yes" : "no");
  if (version == VERSION_V2) {
    printf("  method: unwrap file key from passphrase or recovery key, then verify/decrypt the full ciphertext\n");
  } else {
    printf("  method: unwrap file key from passphrase or recovery key, verify header, then verify/decrypt each chunk\n");
  }
  if (recovery_slots > 0u) {
    printf("  recovery_key_file_required: yes\n");
    printf("  recovery_key_file_format: %s + 64 hex chars\n", RECOVERY_KEY_FILE_MAGIC);
  }
}

static void encrypt_command(const char *input_path,
                            const char *output_path,
                            uint32_t iterations,
                            const Options *opts) {
  FILE *in = NULL;
  FILE *out = NULL;
  char *temp_path = NULL;
  char *owned_output = NULL;
  char *passphrase = NULL;
  uint8_t passphrase_key[MASTER_KEY_LEN];
  uint8_t recovery_key[RECOVERY_KEY_LEN];
  uint8_t file_key[FILE_KEY_LEN];
  uint8_t header_bytes[V3_FIXED_HEADER_LEN];
  uint8_t header_tag[TAG_LEN];
  uint8_t chunk_tag[TAG_LEN];
  uint8_t chunk_meta[V3_CHUNK_META_LEN];
  uint8_t chunk_iv[IV_LEN];
  VaultHeaderV3 hdr;
  VaultKeySlotV2 slots[MAX_KEY_SLOTS];
  uint8_t *plain_buf = NULL;
  uint8_t *next_plain_buf = NULL;
  uint8_t *cipher_buf = NULL;
  size_t current_len;
  uint64_t chunk_index = 0;
  uint32_t slot_count = 0;
  VaultKeySlotV2 slot;

  memset(passphrase_key, 0, sizeof(passphrase_key));
  memset(recovery_key, 0, sizeof(recovery_key));
  memset(file_key, 0, sizeof(file_key));
  memset(slots, 0, sizeof(slots));
  memset(&slot, 0, sizeof(slot));
  memset(header_tag, 0, sizeof(header_tag));
  memset(chunk_tag, 0, sizeof(chunk_tag));

  if (input_path == NULL) {
    usage(stderr, 2);
  }
  if (iterations < MIN_ITERATIONS) {
    fail_msg("iteration count is too low");
  }

  if (output_path == NULL) {
    if (strcmp(input_path, "-") == 0) {
      fail_msg("encrypting from stdin requires -o OUTPUT");
    }
    owned_output = default_encrypt_output(input_path);
    output_path = owned_output;
  }
  if (strcmp(output_path, "-") == 0) {
    fail_msg("encrypt requires a file output path");
  }
  if (strcmp(input_path, "-") != 0 && strcmp(input_path, output_path) == 0) {
    fail_msg("input and output paths must differ");
  }

  passphrase = prompt_passphrase("Passphrase: ", 1, opts->require_tty);
  fill_header_v3(&hdr, iterations);
  random_bytes(file_key, sizeof(file_key));
  derive_master_key(passphrase, hdr.salt, hdr.iterations, passphrase_key);
  wrap_file_key_for_slot(passphrase_key, SLOT_TYPE_PASSPHRASE, file_key, &slot);
  append_slot(slots, &slot_count, &slot);
  if (opts->recovery_key_out_path != NULL) {
    random_bytes(recovery_key, sizeof(recovery_key));
    wrap_file_key_for_slot(recovery_key, SLOT_TYPE_RECOVERY, file_key, &slot);
    append_slot(slots, &slot_count, &slot);
  }
  set_slot_count_v3(&hdr, slot_count);
  serialize_header_v3(&hdr, header_bytes);
  compute_v3_header_tag(file_key + PAYLOAD_ENC_KEY_LEN, header_bytes, slots, hdr.slot_count, header_tag);
  lock_memory_best_effort(passphrase_key, sizeof(passphrase_key));
  lock_memory_best_effort(recovery_key, sizeof(recovery_key));
  lock_memory_best_effort(file_key, sizeof(file_key));
  plain_buf = (uint8_t *)malloc(hdr.chunk_size);
  next_plain_buf = (uint8_t *)malloc(hdr.chunk_size);
  cipher_buf = (uint8_t *)malloc(hdr.chunk_size);
  if (plain_buf == NULL || next_plain_buf == NULL || cipher_buf == NULL) {
    fail_msg("out of memory");
  }

  if (strcmp(input_path, "-") == 0) {
    in = stdin;
  } else {
    in = open_input_file(input_path);
  }
  out = open_output_temp(output_path, &temp_path, opts->force);

  write_exact(out, header_bytes, sizeof(header_bytes), "write header");
  {
    uint32_t i;
    for (i = 0; i < hdr.slot_count; ++i) {
      write_exact(out, slots[i].header_bytes, sizeof(slots[i].header_bytes), "write key slot");
      write_exact(out, slots[i].wrapped_key, slots[i].wrapped_key_len, "write wrapped key");
    }
  }
  write_exact(out, header_tag, sizeof(header_tag), "write header tag");

  current_len = fread(plain_buf, 1, hdr.chunk_size, in);
  if (ferror(in)) {
    fail_errno("read input");
  }

  for (;;) {
    size_t next_len = 0;
    uint32_t flags = 0;

    if (current_len == 0u && feof(in)) {
      flags = V3_CHUNK_FINAL_FLAG;
    } else {
      next_len = fread(next_plain_buf, 1, hdr.chunk_size, in);
      if (ferror(in)) {
        fail_errno("read input");
      }
      if (next_len == 0u && feof(in)) {
        flags = V3_CHUNK_FINAL_FLAG;
      }
    }

    if (current_len > 0u) {
      CCCryptorRef cryptor;
      CCCryptorStatus status;
      size_t produced = 0;

      derive_chunk_iv(hdr.iv, chunk_index, chunk_iv);
      cryptor = create_ctr_cryptor(kCCEncrypt, file_key, chunk_iv);
      status = CCCryptorUpdate(cryptor,
                               plain_buf,
                               current_len,
                               cipher_buf,
                               hdr.chunk_size,
                               &produced);
      if (status != kCCSuccess || produced != current_len) {
        CCCryptorRelease(cryptor);
        fail_msg("chunk encryption failed");
      }
      CCCryptorRelease(cryptor);
    }

    write_be32(chunk_meta + 0, (uint32_t)current_len);
    write_be32(chunk_meta + 4, flags);
    compute_v3_chunk_tag(file_key + PAYLOAD_ENC_KEY_LEN,
                         hdr.iv,
                         chunk_index,
                         flags,
                         cipher_buf,
                         (uint32_t)current_len,
                         chunk_tag);
    write_exact(out, chunk_meta, sizeof(chunk_meta), "write chunk metadata");
    if (current_len > 0u) {
      write_exact(out, cipher_buf, current_len, "write chunk ciphertext");
    }
    write_exact(out, chunk_tag, sizeof(chunk_tag), "write chunk tag");

    if ((flags & V3_CHUNK_FINAL_FLAG) != 0u) {
      break;
    }

    {
      uint8_t *swap = plain_buf;
      plain_buf = next_plain_buf;
      next_plain_buf = swap;
      current_len = next_len;
      chunk_index++;
    }
  }

  finalize_output_file(out, temp_path, output_path);
  out = NULL;
  temp_path = NULL;
  if (opts->recovery_key_out_path != NULL) {
    write_recovery_key_file(opts->recovery_key_out_path, recovery_key);
  }

  if (in != NULL && in != stdin) {
    fclose(in);
  }
  free(plain_buf);
  free(next_plain_buf);
  free(cipher_buf);
  secure_release_buffer(passphrase_key, sizeof(passphrase_key));
  secure_release_buffer(recovery_key, sizeof(recovery_key));
  secure_release_buffer(file_key, sizeof(file_key));
  secure_free_string(&passphrase);
  free(owned_output);
}

static void copy_file_to_stream(FILE *src, FILE *dst) {
  uint8_t buf[CHUNK_SIZE];
  size_t nread;

  rewind(src);
  while ((nread = fread(buf, 1, sizeof(buf), src)) > 0) {
    write_exact(dst, buf, nread, "write output");
  }
  if (ferror(src)) {
    fail_errno("read decrypted temporary file");
  }
  if (fflush(dst) != 0) {
    fail_errno("flush output");
  }
}

static void decrypt_v1(FILE *in,
                       const char *input_path,
                       const char *output_path,
                       const Options *opts,
                       uint64_t total_size,
                       const uint8_t first_magic[MAGIC_LEN]) {
  FILE *tmp = NULL;
  char *temp_path = NULL;
  char *passphrase = NULL;
  uint8_t header_bytes[V1_HEADER_LEN];
  uint8_t expected_tag[TAG_LEN];
  uint8_t actual_tag[TAG_LEN];
  uint8_t enc_key[PAYLOAD_ENC_KEY_LEN];
  uint8_t mac_key[PAYLOAD_MAC_KEY_LEN];
  uint8_t inbuf[CHUNK_SIZE];
  uint8_t outbuf[CHUNK_SIZE + 32];
  VaultHeaderV1 hdr;
  CCCryptorRef cryptor = NULL;
  CCHmacContext hmac;
  uint64_t ciphertext_len;
  uint64_t remaining;

  memset(enc_key, 0, sizeof(enc_key));
  memset(mac_key, 0, sizeof(mac_key));

  if (total_size < V1_HEADER_LEN + TAG_LEN) {
    fail_msg("file is too small to be a VLTENC01 ciphertext");
  }
  ciphertext_len = total_size - V1_HEADER_LEN - TAG_LEN;

  memcpy(header_bytes, first_magic, MAGIC_LEN);
  read_exact(in, header_bytes + MAGIC_LEN, V1_HEADER_LEN - MAGIC_LEN, "read header");
  parse_header_v1(header_bytes, &hdr);

  passphrase = prompt_passphrase("Passphrase: ", 0, opts->require_tty);
  derive_legacy_keys(passphrase, hdr.salt, hdr.iterations, enc_key, mac_key);
  cryptor = create_ctr_cryptor(kCCDecrypt, enc_key, hdr.iv);
  lock_memory_best_effort(enc_key, sizeof(enc_key));
  lock_memory_best_effort(mac_key, sizeof(mac_key));

  CCHmacInit(&hmac, kCCHmacAlgSHA256, mac_key, PAYLOAD_MAC_KEY_LEN);
  CCHmacUpdate(&hmac, header_bytes, sizeof(header_bytes));

  if (output_path == NULL || strcmp(output_path, "-") == 0) {
    tmp = tmpfile();
    if (tmp == NULL) {
      fail_errno("tmpfile");
    }
  } else {
    tmp = open_output_temp(output_path, &temp_path, opts->force);
  }

  remaining = ciphertext_len;
  while (remaining > 0) {
    size_t want = remaining > sizeof(inbuf) ? sizeof(inbuf) : (size_t)remaining;
    size_t produced = 0;
    CCCryptorStatus status;

    read_exact(in, inbuf, want, "read ciphertext");
    CCHmacUpdate(&hmac, inbuf, want);

    status = CCCryptorUpdate(cryptor,
                             inbuf,
                             want,
                             outbuf,
                             sizeof(outbuf),
                             &produced);
    if (status != kCCSuccess) {
      fail_msg("decryption failed");
    }
    if (produced > 0) {
      write_exact(tmp, outbuf, produced, "write decrypted data");
    }
    remaining -= want;
  }

  {
    size_t produced = 0;
    CCCryptorStatus status = CCCryptorFinal(cryptor,
                                            outbuf,
                                            sizeof(outbuf),
                                            &produced);
    if (status != kCCSuccess) {
      fail_msg("final decryption step failed");
    }
    if (produced > 0) {
      write_exact(tmp, outbuf, produced, "write final decrypted data");
    }
  }

  read_exact(in, expected_tag, sizeof(expected_tag), "read authentication tag");
  CCHmacFinal(&hmac, actual_tag);
  if (!constant_time_eq(expected_tag, actual_tag, sizeof(expected_tag))) {
    if (temp_path != NULL) {
      fclose(tmp);
      unlink(temp_path);
    } else if (tmp != NULL) {
      fclose(tmp);
    }
    fail_msg("authentication failed: wrong passphrase or corrupted file");
  }

  if (temp_path != NULL) {
    finalize_output_file(tmp, temp_path, output_path);
  } else {
    copy_file_to_stream(tmp, stdout);
    fclose(tmp);
  }

  fclose(in);
  if (cryptor != NULL) {
    CCCryptorRelease(cryptor);
  }
  secure_release_buffer(enc_key, sizeof(enc_key));
  secure_release_buffer(mac_key, sizeof(mac_key));
  secure_free_string(&passphrase);
  (void)input_path;
}

static void decrypt_v2(FILE *in,
                       const char *output_path,
                       const Options *opts,
                       uint64_t total_size,
                       const uint8_t first_magic[MAGIC_LEN]) {
  FILE *tmp = NULL;
  char *temp_path = NULL;
  uint8_t header_bytes[V2_FIXED_HEADER_LEN];
  uint8_t expected_tag[TAG_LEN];
  uint8_t actual_tag[TAG_LEN];
  uint8_t file_key[FILE_KEY_LEN];
  uint8_t inbuf[CHUNK_SIZE];
  uint8_t outbuf[CHUNK_SIZE + 32];
  VaultHeaderV2 hdr;
  VaultKeySlotV2 slots[MAX_KEY_SLOTS];
  CCCryptorRef cryptor = NULL;
  CCHmacContext hmac;
  uint64_t slot_bytes_len;
  uint64_t ciphertext_len;
  uint64_t remaining;

  memset(file_key, 0, sizeof(file_key));
  memset(slots, 0, sizeof(slots));

  if (total_size < V2_FIXED_HEADER_LEN + V2_SLOT_HEADER_LEN + TAG_LEN) {
    fail_msg("file is too small to be a VLTENC02 ciphertext");
  }

  memcpy(header_bytes, first_magic, MAGIC_LEN);
  read_exact(in, header_bytes + MAGIC_LEN, V2_FIXED_HEADER_LEN - MAGIC_LEN, "read header");
  parse_header_v2(header_bytes, &hdr);
  slot_bytes_len = read_slots(in, hdr.slot_count, slots);

  if (total_size < V2_FIXED_HEADER_LEN + slot_bytes_len + TAG_LEN) {
    fail_msg("VLTENC02 container is truncated");
  }
  ciphertext_len = total_size - V2_FIXED_HEADER_LEN - slot_bytes_len - TAG_LEN;
  unwrap_file_key_from_slots(hdr.salt, hdr.iterations, hdr.slot_count, slots, opts, file_key);
  cryptor = create_ctr_cryptor(kCCDecrypt, file_key, hdr.iv);
  lock_memory_best_effort(file_key, sizeof(file_key));

  CCHmacInit(&hmac, kCCHmacAlgSHA256, file_key + PAYLOAD_ENC_KEY_LEN, PAYLOAD_MAC_KEY_LEN);
  CCHmacUpdate(&hmac, header_bytes, sizeof(header_bytes));
  hmac_update_v2_slots(&hmac, slots, hdr.slot_count);

  if (output_path == NULL || strcmp(output_path, "-") == 0) {
    tmp = tmpfile();
    if (tmp == NULL) {
      fail_errno("tmpfile");
    }
  } else {
    tmp = open_output_temp(output_path, &temp_path, opts->force);
  }

  remaining = ciphertext_len;
  while (remaining > 0) {
    size_t want = remaining > sizeof(inbuf) ? sizeof(inbuf) : (size_t)remaining;
    size_t produced = 0;
    CCCryptorStatus status;

    read_exact(in, inbuf, want, "read ciphertext");
    CCHmacUpdate(&hmac, inbuf, want);

    status = CCCryptorUpdate(cryptor,
                             inbuf,
                             want,
                             outbuf,
                             sizeof(outbuf),
                             &produced);
    if (status != kCCSuccess) {
      fail_msg("decryption failed");
    }
    if (produced > 0) {
      write_exact(tmp, outbuf, produced, "write decrypted data");
    }
    remaining -= want;
  }

  {
    size_t produced = 0;
    CCCryptorStatus status = CCCryptorFinal(cryptor,
                                            outbuf,
                                            sizeof(outbuf),
                                            &produced);
    if (status != kCCSuccess) {
      fail_msg("final decryption step failed");
    }
    if (produced > 0) {
      write_exact(tmp, outbuf, produced, "write final decrypted data");
    }
  }

  read_exact(in, expected_tag, sizeof(expected_tag), "read authentication tag");
  CCHmacFinal(&hmac, actual_tag);
  if (!constant_time_eq(expected_tag, actual_tag, sizeof(expected_tag))) {
    if (temp_path != NULL) {
      fclose(tmp);
      unlink(temp_path);
    } else if (tmp != NULL) {
      fclose(tmp);
    }
    fail_msg("authentication failed: wrong passphrase or corrupted file");
  }

  if (temp_path != NULL) {
    finalize_output_file(tmp, temp_path, output_path);
  } else {
    copy_file_to_stream(tmp, stdout);
    fclose(tmp);
  }

  fclose(in);
  if (cryptor != NULL) {
    CCCryptorRelease(cryptor);
  }
  secure_release_buffer(file_key, sizeof(file_key));
}

static void decrypt_v3(FILE *in,
                       const char *output_path,
                       const Options *opts,
                       uint64_t total_size,
                       const uint8_t first_magic[MAGIC_LEN]) {
  FILE *out = NULL;
  char *temp_path = NULL;
  uint8_t header_bytes[V3_FIXED_HEADER_LEN];
  uint8_t expected_header_tag[TAG_LEN];
  uint8_t actual_header_tag[TAG_LEN];
  uint8_t expected_chunk_tag[TAG_LEN];
  uint8_t actual_chunk_tag[TAG_LEN];
  uint8_t chunk_meta[V3_CHUNK_META_LEN];
  uint8_t chunk_iv[IV_LEN];
  uint8_t file_key[FILE_KEY_LEN];
  uint8_t *cipher_buf = NULL;
  uint8_t *plain_buf = NULL;
  VaultHeaderV3 hdr;
  VaultKeySlotV2 slots[MAX_KEY_SLOTS];
  uint64_t slot_bytes_len;
  uint64_t chunk_index = 0;

  (void)total_size;
  memset(file_key, 0, sizeof(file_key));
  memset(slots, 0, sizeof(slots));

  memcpy(header_bytes, first_magic, MAGIC_LEN);
  read_exact(in, header_bytes + MAGIC_LEN, V3_FIXED_HEADER_LEN - MAGIC_LEN, "read header");
  parse_header_v3(header_bytes, &hdr);
  slot_bytes_len = read_slots(in, hdr.slot_count, slots);
  (void)slot_bytes_len;
  read_exact(in, expected_header_tag, sizeof(expected_header_tag), "read header tag");

  unwrap_file_key_from_slots(hdr.salt, hdr.iterations, hdr.slot_count, slots, opts, file_key);
  lock_memory_best_effort(file_key, sizeof(file_key));
  compute_v3_header_tag(file_key + PAYLOAD_ENC_KEY_LEN, header_bytes, slots, hdr.slot_count, actual_header_tag);
  if (!constant_time_eq(expected_header_tag, actual_header_tag, sizeof(expected_header_tag))) {
    fail_msg("authentication failed: wrong passphrase/recovery key or corrupted header");
  }

  cipher_buf = (uint8_t *)malloc(hdr.chunk_size);
  plain_buf = (uint8_t *)malloc(hdr.chunk_size);
  if (cipher_buf == NULL || plain_buf == NULL) {
    fail_msg("out of memory");
  }

  if (output_path == NULL || strcmp(output_path, "-") == 0) {
    out = stdout;
  } else {
    out = open_output_temp(output_path, &temp_path, opts->force);
  }

  for (;;) {
    uint32_t chunk_len;
    uint32_t flags;

    read_exact(in, chunk_meta, sizeof(chunk_meta), "read chunk metadata");
    chunk_len = read_be32(chunk_meta + 0);
    flags = read_be32(chunk_meta + 4);
    if (chunk_len > hdr.chunk_size) {
      if (temp_path != NULL) {
        fclose(out);
        unlink(temp_path);
      }
      fail_msg("chunk length exceeds advertised chunk size");
    }
    if ((flags & ~V3_CHUNK_FINAL_FLAG) != 0u) {
      if (temp_path != NULL) {
        fclose(out);
        unlink(temp_path);
      }
      fail_msg("unsupported chunk flags");
    }

    if (chunk_len > 0u) {
      read_exact(in, cipher_buf, chunk_len, "read chunk ciphertext");
    }
    read_exact(in, expected_chunk_tag, sizeof(expected_chunk_tag), "read chunk tag");
    compute_v3_chunk_tag(file_key + PAYLOAD_ENC_KEY_LEN,
                         hdr.iv,
                         chunk_index,
                         flags,
                         cipher_buf,
                         chunk_len,
                         actual_chunk_tag);
    if (!constant_time_eq(expected_chunk_tag, actual_chunk_tag, sizeof(expected_chunk_tag))) {
      if (temp_path != NULL) {
        fclose(out);
        unlink(temp_path);
      }
      fail_msg("authentication failed: chunk verification failed");
    }

    if (chunk_len > 0u) {
      CCCryptorRef cryptor;
      CCCryptorStatus status;
      size_t produced = 0;

      derive_chunk_iv(hdr.iv, chunk_index, chunk_iv);
      cryptor = create_ctr_cryptor(kCCDecrypt, file_key, chunk_iv);
      status = CCCryptorUpdate(cryptor,
                               cipher_buf,
                               chunk_len,
                               plain_buf,
                               hdr.chunk_size,
                               &produced);
      CCCryptorRelease(cryptor);
      if (status != kCCSuccess || produced != chunk_len) {
        if (temp_path != NULL) {
          fclose(out);
          unlink(temp_path);
        }
        fail_msg("chunk decryption failed");
      }
      write_exact(out, plain_buf, produced, "write decrypted data");
    }

    if ((flags & V3_CHUNK_FINAL_FLAG) != 0u) {
      int extra = fgetc(in);
      if (extra != EOF) {
        if (temp_path != NULL) {
          fclose(out);
          unlink(temp_path);
        }
        fail_msg("trailing data after final chunk");
      }
      if (ferror(in)) {
        if (temp_path != NULL) {
          fclose(out);
          unlink(temp_path);
        }
        fail_errno("read final chunk trailer");
      }
      break;
    }

    chunk_index++;
  }

  if (temp_path != NULL) {
    finalize_output_file(out, temp_path, output_path);
  } else if (fflush(out) != 0) {
    fail_errno("flush output");
  }

  fclose(in);
  free(cipher_buf);
  free(plain_buf);
  secure_release_buffer(file_key, sizeof(file_key));
}

static void decrypt_command(const char *input_path, const char *output_path, const Options *opts) {
  FILE *in = NULL;
  uint8_t magic[MAGIC_LEN];
  VaultFormat format;
  uint64_t total_size;

  if (input_path == NULL) {
    usage(stderr, 2);
  }
  if (strcmp(input_path, "-") == 0) {
    fail_msg("decrypt requires a regular input file");
  }
  if ((output_path == NULL || (strcmp(output_path, "-") == 0 && !opts->allow_stdout))) {
    fail_msg("decrypt requires -o PATH or explicit stdout via -o - or --stdout");
  }
  if (output_path != NULL && strcmp(output_path, "-") != 0 && strcmp(input_path, output_path) == 0) {
    fail_msg("input and output paths must differ");
  }

  total_size = input_file_size(input_path);
  if (total_size < MAGIC_LEN + TAG_LEN) {
    fail_msg("file is too small to be a vaultcrypt ciphertext");
  }

  in = open_input_file(input_path);
  read_exact(in, magic, sizeof(magic), "read magic");
  format = detect_format(magic);
  if (format == FORMAT_UNKNOWN) {
    fail_msg("unsupported vaultcrypt file format");
  }

  if (format == FORMAT_V1) {
    if (opts->recovery_key_path != NULL) {
      fail_msg("recovery-key unlock is only supported for VLTENC02/VLTENC03 files");
    }
    decrypt_v1(in, input_path, output_path, opts, total_size, magic);
    return;
  }
  if (format == FORMAT_V2) {
    decrypt_v2(in, output_path, opts, total_size, magic);
    return;
  }
  decrypt_v3(in, output_path, opts, total_size, magic);
}

static void rewrap_v2_command(const char *input_path,
                              const char *output_path,
                              uint32_t iterations,
                              int iterations_explicit,
                              const Options *opts) {
  FILE *in = NULL;
  FILE *out = NULL;
  char *temp_path = NULL;
  char *new_passphrase = NULL;
  uint8_t magic[MAGIC_LEN];
  uint8_t old_header_bytes[V2_FIXED_HEADER_LEN];
  uint8_t new_header_bytes[V2_FIXED_HEADER_LEN];
  uint8_t expected_tag[TAG_LEN];
  uint8_t actual_old_tag[TAG_LEN];
  uint8_t new_tag[TAG_LEN];
  uint8_t new_passphrase_key[MASTER_KEY_LEN];
  uint8_t new_recovery_key[RECOVERY_KEY_LEN];
  uint8_t file_key[FILE_KEY_LEN];
  uint8_t buf[CHUNK_SIZE];
  VaultHeaderV2 old_hdr;
  VaultHeaderV2 new_hdr;
  VaultKeySlotV2 old_slots[MAX_KEY_SLOTS];
  VaultKeySlotV2 new_slots[MAX_KEY_SLOTS];
  CCHmacContext old_hmac;
  CCHmacContext new_hmac;
  uint64_t total_size;
  uint64_t slot_bytes_len;
  uint64_t ciphertext_len;
  uint64_t remaining;
  uint32_t new_slot_count = 0;
  VaultKeySlotV2 slot;

  memset(new_passphrase_key, 0, sizeof(new_passphrase_key));
  memset(new_recovery_key, 0, sizeof(new_recovery_key));
  memset(file_key, 0, sizeof(file_key));
  memset(old_slots, 0, sizeof(old_slots));
  memset(new_slots, 0, sizeof(new_slots));
  memset(&slot, 0, sizeof(slot));

  if (input_path == NULL) {
    usage(stderr, 2);
  }
  if (strcmp(input_path, "-") == 0) {
    fail_msg("rewrap requires a regular input file");
  }
  if (output_path == NULL) {
    output_path = input_path;
  }
  if (strcmp(output_path, "-") == 0) {
    fail_msg("rewrap requires a file output path");
  }
  if (iterations_explicit && iterations < MIN_ITERATIONS) {
    fail_msg("iteration count is too low");
  }

  total_size = input_file_size(input_path);
  if (total_size < V2_FIXED_HEADER_LEN + V2_SLOT_HEADER_LEN + TAG_LEN) {
    fail_msg("file is too small to be a VLTENC02 ciphertext");
  }

  in = open_input_file(input_path);
  read_exact(in, magic, sizeof(magic), "read magic");
  if (detect_format(magic) != FORMAT_V2) {
    fail_msg("rewrap only supports VLTENC02 files");
  }

  memcpy(old_header_bytes, magic, MAGIC_LEN);
  read_exact(in,
             old_header_bytes + MAGIC_LEN,
             V2_FIXED_HEADER_LEN - MAGIC_LEN,
             "read header");
  parse_header_v2(old_header_bytes, &old_hdr);
  slot_bytes_len = read_slots(in, old_hdr.slot_count, old_slots);
  if (total_size < V2_FIXED_HEADER_LEN + slot_bytes_len + TAG_LEN) {
    fail_msg("VLTENC02 container is truncated");
  }
  ciphertext_len = total_size - V2_FIXED_HEADER_LEN - slot_bytes_len - TAG_LEN;
  unwrap_file_key_from_slots(old_hdr.salt, old_hdr.iterations, old_hdr.slot_count, old_slots, opts, file_key);
  lock_memory_best_effort(file_key, sizeof(file_key));

  new_passphrase = prompt_passphrase("New passphrase: ", 1, opts->require_tty);
  new_hdr = old_hdr;
  new_hdr.iterations = iterations_explicit ? iterations : old_hdr.iterations;
  random_bytes(new_hdr.salt, sizeof(new_hdr.salt));
  derive_master_key(new_passphrase, new_hdr.salt, new_hdr.iterations, new_passphrase_key);
  wrap_file_key_for_slot(new_passphrase_key, SLOT_TYPE_PASSPHRASE, file_key, &slot);
  append_slot(new_slots, &new_slot_count, &slot);
  append_slots_except_type(new_slots, &new_slot_count, old_slots, old_hdr.slot_count, SLOT_TYPE_PASSPHRASE);

  if (opts->recovery_key_out_path != NULL) {
    uint32_t i;
    uint32_t compacted_count = 0;
    VaultKeySlotV2 compacted_slots[MAX_KEY_SLOTS];

    memset(compacted_slots, 0, sizeof(compacted_slots));
    for (i = 0; i < new_slot_count; ++i) {
      if (new_slots[i].type == SLOT_TYPE_RECOVERY) {
        continue;
      }
      compacted_slots[compacted_count++] = new_slots[i];
    }
    memcpy(new_slots, compacted_slots, sizeof(compacted_slots));
    new_slot_count = compacted_count;

    random_bytes(new_recovery_key, sizeof(new_recovery_key));
    wrap_file_key_for_slot(new_recovery_key, SLOT_TYPE_RECOVERY, file_key, &slot);
    append_slot(new_slots, &new_slot_count, &slot);
  }

  set_slot_count(&new_hdr, new_slot_count);
  serialize_header_v2(&new_hdr, new_header_bytes);
  lock_memory_best_effort(new_passphrase_key, sizeof(new_passphrase_key));
  lock_memory_best_effort(new_recovery_key, sizeof(new_recovery_key));

  out = open_output_temp(output_path, &temp_path, opts->force);
  write_exact(out, new_header_bytes, sizeof(new_header_bytes), "write header");
  {
    uint32_t i;
    for (i = 0; i < new_hdr.slot_count; ++i) {
      write_exact(out, new_slots[i].header_bytes, sizeof(new_slots[i].header_bytes), "write key slot");
      write_exact(out, new_slots[i].wrapped_key, new_slots[i].wrapped_key_len, "write wrapped key");
    }
  }

  CCHmacInit(&old_hmac, kCCHmacAlgSHA256, file_key + PAYLOAD_ENC_KEY_LEN, PAYLOAD_MAC_KEY_LEN);
  CCHmacUpdate(&old_hmac, old_header_bytes, sizeof(old_header_bytes));
  hmac_update_v2_slots(&old_hmac, old_slots, old_hdr.slot_count);

  CCHmacInit(&new_hmac, kCCHmacAlgSHA256, file_key + PAYLOAD_ENC_KEY_LEN, PAYLOAD_MAC_KEY_LEN);
  CCHmacUpdate(&new_hmac, new_header_bytes, sizeof(new_header_bytes));
  hmac_update_v2_slots(&new_hmac, new_slots, new_hdr.slot_count);

  remaining = ciphertext_len;
  while (remaining > 0) {
    size_t want = remaining > sizeof(buf) ? sizeof(buf) : (size_t)remaining;

    read_exact(in, buf, want, "read ciphertext");
    CCHmacUpdate(&old_hmac, buf, want);
    CCHmacUpdate(&new_hmac, buf, want);
    write_exact(out, buf, want, "write ciphertext");
    remaining -= want;
  }

  read_exact(in, expected_tag, sizeof(expected_tag), "read authentication tag");
  CCHmacFinal(&old_hmac, actual_old_tag);
  if (!constant_time_eq(expected_tag, actual_old_tag, sizeof(expected_tag))) {
    fclose(out);
    unlink(temp_path);
    fclose(in);
    fail_msg("authentication failed: wrong passphrase or corrupted file");
  }

  CCHmacFinal(&new_hmac, new_tag);
  write_exact(out, new_tag, sizeof(new_tag), "write tag");
  fclose(in);
  finalize_output_file(out, temp_path, output_path);
  if (opts->recovery_key_out_path != NULL) {
    write_recovery_key_file(opts->recovery_key_out_path, new_recovery_key);
  }

  secure_release_buffer(new_passphrase_key, sizeof(new_passphrase_key));
  secure_release_buffer(new_recovery_key, sizeof(new_recovery_key));
  secure_release_buffer(file_key, sizeof(file_key));
  secure_free_string(&new_passphrase);
}

static void rewrap_v3_command(const char *input_path,
                              const char *output_path,
                              uint32_t iterations,
                              int iterations_explicit,
                              const Options *opts) {
  FILE *in = NULL;
  FILE *out = NULL;
  char *temp_path = NULL;
  char *new_passphrase = NULL;
  uint8_t magic[MAGIC_LEN];
  uint8_t old_header_bytes[V3_FIXED_HEADER_LEN];
  uint8_t new_header_bytes[V3_FIXED_HEADER_LEN];
  uint8_t expected_header_tag[TAG_LEN];
  uint8_t actual_old_header_tag[TAG_LEN];
  uint8_t new_header_tag[TAG_LEN];
  uint8_t expected_chunk_tag[TAG_LEN];
  uint8_t actual_chunk_tag[TAG_LEN];
  uint8_t chunk_meta[V3_CHUNK_META_LEN];
  uint8_t new_passphrase_key[MASTER_KEY_LEN];
  uint8_t new_recovery_key[RECOVERY_KEY_LEN];
  uint8_t file_key[FILE_KEY_LEN];
  uint8_t *cipher_buf = NULL;
  VaultHeaderV3 old_hdr;
  VaultHeaderV3 new_hdr;
  VaultKeySlotV2 old_slots[MAX_KEY_SLOTS];
  VaultKeySlotV2 new_slots[MAX_KEY_SLOTS];
  uint32_t new_slot_count = 0;
  VaultKeySlotV2 slot;
  uint64_t chunk_index = 0;

  memset(new_passphrase_key, 0, sizeof(new_passphrase_key));
  memset(new_recovery_key, 0, sizeof(new_recovery_key));
  memset(file_key, 0, sizeof(file_key));
  memset(old_slots, 0, sizeof(old_slots));
  memset(new_slots, 0, sizeof(new_slots));
  memset(&slot, 0, sizeof(slot));

  if (input_path == NULL) {
    usage(stderr, 2);
  }
  if (strcmp(input_path, "-") == 0) {
    fail_msg("rewrap requires a regular input file");
  }
  if (output_path == NULL) {
    output_path = input_path;
  }
  if (strcmp(output_path, "-") == 0) {
    fail_msg("rewrap requires a file output path");
  }
  if (iterations_explicit && iterations < MIN_ITERATIONS) {
    fail_msg("iteration count is too low");
  }

  in = open_input_file(input_path);
  read_exact(in, magic, sizeof(magic), "read magic");
  if (detect_format(magic) != FORMAT_V3) {
    fail_msg("rewrap v3 requires a VLTENC03 file");
  }

  memcpy(old_header_bytes, magic, MAGIC_LEN);
  read_exact(in, old_header_bytes + MAGIC_LEN, V3_FIXED_HEADER_LEN - MAGIC_LEN, "read header");
  parse_header_v3(old_header_bytes, &old_hdr);
  (void)read_slots(in, old_hdr.slot_count, old_slots);
  read_exact(in, expected_header_tag, sizeof(expected_header_tag), "read header tag");
  unwrap_file_key_from_slots(old_hdr.salt, old_hdr.iterations, old_hdr.slot_count, old_slots, opts, file_key);
  lock_memory_best_effort(file_key, sizeof(file_key));
  compute_v3_header_tag(file_key + PAYLOAD_ENC_KEY_LEN,
                        old_header_bytes,
                        old_slots,
                        old_hdr.slot_count,
                        actual_old_header_tag);
  if (!constant_time_eq(expected_header_tag, actual_old_header_tag, sizeof(expected_header_tag))) {
    fail_msg("authentication failed: wrong passphrase/recovery key or corrupted header");
  }

  cipher_buf = (uint8_t *)malloc(old_hdr.chunk_size);
  if (cipher_buf == NULL) {
    fail_msg("out of memory");
  }

  new_passphrase = prompt_passphrase("New passphrase: ", 1, opts->require_tty);
  new_hdr = old_hdr;
  new_hdr.iterations = iterations_explicit ? iterations : old_hdr.iterations;
  random_bytes(new_hdr.salt, sizeof(new_hdr.salt));
  derive_master_key(new_passphrase, new_hdr.salt, new_hdr.iterations, new_passphrase_key);
  wrap_file_key_for_slot(new_passphrase_key, SLOT_TYPE_PASSPHRASE, file_key, &slot);
  append_slot(new_slots, &new_slot_count, &slot);
  append_slots_except_type(new_slots, &new_slot_count, old_slots, old_hdr.slot_count, SLOT_TYPE_PASSPHRASE);
  if (opts->recovery_key_out_path != NULL) {
    uint32_t i;
    uint32_t compacted_count = 0;
    VaultKeySlotV2 compacted_slots[MAX_KEY_SLOTS];

    memset(compacted_slots, 0, sizeof(compacted_slots));
    for (i = 0; i < new_slot_count; ++i) {
      if (new_slots[i].type == SLOT_TYPE_RECOVERY) {
        continue;
      }
      compacted_slots[compacted_count++] = new_slots[i];
    }
    memcpy(new_slots, compacted_slots, sizeof(compacted_slots));
    new_slot_count = compacted_count;

    random_bytes(new_recovery_key, sizeof(new_recovery_key));
    wrap_file_key_for_slot(new_recovery_key, SLOT_TYPE_RECOVERY, file_key, &slot);
    append_slot(new_slots, &new_slot_count, &slot);
  }
  set_slot_count_v3(&new_hdr, new_slot_count);
  serialize_header_v3(&new_hdr, new_header_bytes);
  compute_v3_header_tag(file_key + PAYLOAD_ENC_KEY_LEN,
                        new_header_bytes,
                        new_slots,
                        new_hdr.slot_count,
                        new_header_tag);

  out = open_output_temp(output_path, &temp_path, opts->force);
  write_exact(out, new_header_bytes, sizeof(new_header_bytes), "write header");
  {
    uint32_t i;
    for (i = 0; i < new_hdr.slot_count; ++i) {
      write_exact(out, new_slots[i].header_bytes, sizeof(new_slots[i].header_bytes), "write key slot");
      write_exact(out, new_slots[i].wrapped_key, new_slots[i].wrapped_key_len, "write wrapped key");
    }
  }
  write_exact(out, new_header_tag, sizeof(new_header_tag), "write header tag");

  for (;;) {
    uint32_t chunk_len;
    uint32_t flags;

    read_exact(in, chunk_meta, sizeof(chunk_meta), "read chunk metadata");
    chunk_len = read_be32(chunk_meta + 0);
    flags = read_be32(chunk_meta + 4);
    if (chunk_len > old_hdr.chunk_size || (flags & ~V3_CHUNK_FINAL_FLAG) != 0u) {
      fclose(out);
      unlink(temp_path);
      fail_msg("invalid chunk metadata in VLTENC03 file");
    }
    if (chunk_len > 0u) {
      read_exact(in, cipher_buf, chunk_len, "read chunk ciphertext");
    }
    read_exact(in, expected_chunk_tag, sizeof(expected_chunk_tag), "read chunk tag");
    compute_v3_chunk_tag(file_key + PAYLOAD_ENC_KEY_LEN,
                         old_hdr.iv,
                         chunk_index,
                         flags,
                         cipher_buf,
                         chunk_len,
                         actual_chunk_tag);
    if (!constant_time_eq(expected_chunk_tag, actual_chunk_tag, sizeof(expected_chunk_tag))) {
      fclose(out);
      unlink(temp_path);
      fail_msg("authentication failed: chunk verification failed");
    }

    write_exact(out, chunk_meta, sizeof(chunk_meta), "write chunk metadata");
    if (chunk_len > 0u) {
      write_exact(out, cipher_buf, chunk_len, "write chunk ciphertext");
    }
    write_exact(out, expected_chunk_tag, sizeof(expected_chunk_tag), "write chunk tag");

    if ((flags & V3_CHUNK_FINAL_FLAG) != 0u) {
      int extra = fgetc(in);
      if (extra != EOF) {
        fclose(out);
        unlink(temp_path);
        fail_msg("trailing data after final chunk");
      }
      if (ferror(in)) {
        fclose(out);
        unlink(temp_path);
        fail_errno("read final chunk trailer");
      }
      break;
    }

    chunk_index++;
  }

  fclose(in);
  finalize_output_file(out, temp_path, output_path);
  if (opts->recovery_key_out_path != NULL) {
    write_recovery_key_file(opts->recovery_key_out_path, new_recovery_key);
  }

  free(cipher_buf);
  secure_release_buffer(new_passphrase_key, sizeof(new_passphrase_key));
  secure_release_buffer(new_recovery_key, sizeof(new_recovery_key));
  secure_release_buffer(file_key, sizeof(file_key));
  secure_free_string(&new_passphrase);
}

static void rewrap_command(const char *input_path,
                           const char *output_path,
                           uint32_t iterations,
                           int iterations_explicit,
                           const Options *opts) {
  FILE *in;
  uint8_t magic[MAGIC_LEN];
  VaultFormat format;

  if (input_path == NULL) {
    usage(stderr, 2);
  }

  in = open_input_file(input_path);
  read_exact(in, magic, sizeof(magic), "read magic");
  fclose(in);
  format = detect_format(magic);
  if (format == FORMAT_V2) {
    rewrap_v2_command(input_path, output_path, iterations, iterations_explicit, opts);
    return;
  }
  if (format == FORMAT_V3) {
    rewrap_v3_command(input_path, output_path, iterations, iterations_explicit, opts);
    return;
  }
  fail_msg("rewrap only supports VLTENC02 and VLTENC03 files");
}

static void info_command(const char *input_path, const Options *opts) {
  FILE *in;
  uint8_t magic[MAGIC_LEN];
  VaultFormat format;

  if (input_path == NULL || strcmp(input_path, "-") == 0) {
    fail_msg("info requires a regular input file");
  }

  in = open_input_file(input_path);
  read_exact(in, magic, sizeof(magic), "read magic");
  format = detect_format(magic);
  if (format == FORMAT_UNKNOWN) {
    fclose(in);
    fail_msg("unsupported vaultcrypt file format");
  }

  if (format == FORMAT_V1) {
    uint8_t header_bytes[V1_HEADER_LEN];
    VaultHeaderV1 hdr;

    memcpy(header_bytes, magic, MAGIC_LEN);
    read_exact(in, header_bytes + MAGIC_LEN, V1_HEADER_LEN - MAGIC_LEN, "read header");
    fclose(in);
    parse_header_v1(header_bytes, &hdr);

    if (opts->info_json) {
      printf("{\n"
             "  \"file\": \"%s\",\n"
             "  \"format\": \"VLTENC01\",\n"
             "  \"kdf\": \"PBKDF2-HMAC-SHA256\",\n"
             "  \"cipher\": \"AES-256-CTR\",\n"
             "  \"mac\": \"HMAC-SHA256 (encrypt-then-MAC)\",\n"
             "  \"iterations\": %u,\n"
             "  \"salt_len\": %u,\n"
             "  \"iv_len\": %u,\n"
             "  \"recovery\": {\n"
             "    \"passphrase_only\": true,\n"
             "    \"alternate_recovery_slot\": false,\n"
             "    \"method\": \"derive keys from passphrase, then verify and decrypt the full file\"\n"
             "  }\n"
             "}\n",
             input_path,
             hdr.iterations,
             hdr.salt_len,
             hdr.iv_len);
      return;
    }

    printf("file: %s\n", input_path);
    printf("format: VLTENC01\n");
    printf("kdf: PBKDF2-HMAC-SHA256\n");
    printf("cipher: AES-256-CTR\n");
    printf("mac: HMAC-SHA256 (encrypt-then-MAC)\n");
    printf("iterations: %u\n", hdr.iterations);
    printf("salt_len: %u\n", hdr.salt_len);
    printf("iv_len: %u\n", hdr.iv_len);
    print_recovery_lines_plain(VERSION_V1, 0u);
    return;
  }

  if (format == FORMAT_V2) {
    uint8_t header_bytes[V2_FIXED_HEADER_LEN];
    VaultHeaderV2 hdr;
    VaultKeySlotV2 slots[MAX_KEY_SLOTS];
    uint32_t passphrase_slots;
    uint32_t recovery_slots;

    memcpy(header_bytes, magic, MAGIC_LEN);
    read_exact(in, header_bytes + MAGIC_LEN, V2_FIXED_HEADER_LEN - MAGIC_LEN, "read header");
    parse_header_v2(header_bytes, &hdr);
    memset(slots, 0, sizeof(slots));
    (void)read_slots(in, hdr.slot_count, slots);
    fclose(in);
    passphrase_slots = slot_count_by_type(slots, hdr.slot_count, SLOT_TYPE_PASSPHRASE);
    recovery_slots = slot_count_by_type(slots, hdr.slot_count, SLOT_TYPE_RECOVERY);

    if (opts->info_json) {
      printf("{\n"
             "  \"file\": \"%s\",\n"
             "  \"format\": \"VLTENC02\",\n"
             "  \"kdf\": \"PBKDF2-HMAC-SHA256\",\n"
             "  \"cipher\": \"AES-256-CTR\",\n"
             "  \"mac\": \"HMAC-SHA256 (encrypt-then-MAC)\",\n"
             "  \"wrap\": \"AES Key Wrap (RFC 3394)\",\n"
             "  \"iterations\": %u,\n"
             "  \"salt_len\": %u,\n"
             "  \"iv_len\": %u,\n"
             "  \"key_slots\": %u,\n"
             "  \"passphrase_slots\": %u,\n"
             "  \"recovery_slots\": %u,\n"
             "  \"recovery\": {\n"
             "    \"passphrase_only\": %s,\n"
             "    \"alternate_recovery_slot\": %s,\n"
             "    \"recovery_key_file_required\": %s,\n"
             "    \"recovery_key_file_format\": \"%s + 64 hex chars\",\n"
             "    \"method\": \"unwrap file key from passphrase or recovery key, then verify and decrypt the full ciphertext\"\n"
             "  }\n"
             "}\n",
             input_path,
             hdr.iterations,
             hdr.salt_len,
             hdr.iv_len,
             hdr.slot_count,
             passphrase_slots,
             recovery_slots,
             recovery_slots == 0u ? "true" : "false",
             recovery_slots > 0u ? "true" : "false",
             recovery_slots > 0u ? "true" : "false",
             RECOVERY_KEY_FILE_MAGIC);
      return;
    }

    printf("file: %s\n", input_path);
    printf("format: VLTENC02\n");
    printf("kdf: PBKDF2-HMAC-SHA256\n");
    printf("cipher: AES-256-CTR\n");
    printf("mac: HMAC-SHA256 (encrypt-then-MAC)\n");
    printf("wrap: AES Key Wrap (RFC 3394)\n");
    printf("iterations: %u\n", hdr.iterations);
    printf("salt_len: %u\n", hdr.salt_len);
    printf("iv_len: %u\n", hdr.iv_len);
    printf("key_slots: %u\n", hdr.slot_count);
    printf("passphrase_slots: %u\n", passphrase_slots);
    printf("recovery_slots: %u\n", recovery_slots);
    print_recovery_lines_plain(VERSION_V2, recovery_slots);
    return;
  }

  {
    uint8_t header_bytes[V3_FIXED_HEADER_LEN];
    VaultHeaderV3 hdr;
    VaultKeySlotV2 slots[MAX_KEY_SLOTS];
    uint32_t passphrase_slots;
    uint32_t recovery_slots;

    memcpy(header_bytes, magic, MAGIC_LEN);
    read_exact(in, header_bytes + MAGIC_LEN, V3_FIXED_HEADER_LEN - MAGIC_LEN, "read header");
    parse_header_v3(header_bytes, &hdr);
    memset(slots, 0, sizeof(slots));
    (void)read_slots(in, hdr.slot_count, slots);
    fclose(in);
    passphrase_slots = slot_count_by_type(slots, hdr.slot_count, SLOT_TYPE_PASSPHRASE);
    recovery_slots = slot_count_by_type(slots, hdr.slot_count, SLOT_TYPE_RECOVERY);

    if (opts->info_json) {
      printf("{\n"
             "  \"file\": \"%s\",\n"
             "  \"format\": \"VLTENC03\",\n"
             "  \"kdf\": \"PBKDF2-HMAC-SHA256\",\n"
             "  \"cipher\": \"AES-256-CTR\",\n"
             "  \"mac\": \"HMAC-SHA256 (chunked-stream)\",\n"
             "  \"wrap\": \"AES Key Wrap (RFC 3394)\",\n"
             "  \"iterations\": %u,\n"
             "  \"salt_len\": %u,\n"
             "  \"iv_len\": %u,\n"
             "  \"chunk_size\": %u,\n"
             "  \"key_slots\": %u,\n"
             "  \"passphrase_slots\": %u,\n"
             "  \"recovery_slots\": %u,\n"
             "  \"recovery\": {\n"
             "    \"passphrase_only\": %s,\n"
             "    \"alternate_recovery_slot\": %s,\n"
             "    \"recovery_key_file_required\": %s,\n"
             "    \"recovery_key_file_format\": \"%s + 64 hex chars\",\n"
             "    \"method\": \"unwrap file key from passphrase or recovery key, verify header, then verify and decrypt each chunk\"\n"
             "  }\n"
             "}\n",
             input_path,
             hdr.iterations,
             hdr.salt_len,
             hdr.iv_len,
             hdr.chunk_size,
             hdr.slot_count,
             passphrase_slots,
             recovery_slots,
             recovery_slots == 0u ? "true" : "false",
             recovery_slots > 0u ? "true" : "false",
             recovery_slots > 0u ? "true" : "false",
             RECOVERY_KEY_FILE_MAGIC);
      return;
    }

    printf("file: %s\n", input_path);
    printf("format: VLTENC03\n");
    printf("kdf: PBKDF2-HMAC-SHA256\n");
    printf("cipher: AES-256-CTR\n");
    printf("mac: HMAC-SHA256 (chunked-stream)\n");
    printf("wrap: AES Key Wrap (RFC 3394)\n");
    printf("iterations: %u\n", hdr.iterations);
    printf("salt_len: %u\n", hdr.salt_len);
    printf("iv_len: %u\n", hdr.iv_len);
    printf("chunk_size: %u\n", hdr.chunk_size);
    printf("key_slots: %u\n", hdr.slot_count);
    printf("passphrase_slots: %u\n", passphrase_slots);
    printf("recovery_slots: %u\n", recovery_slots);
    print_recovery_lines_plain(VERSION_V3, recovery_slots);
  }
}

static FILE *tmpfile_or_die(void) {
  FILE *fp = tmpfile();
  if (fp == NULL) {
    fail_errno("tmpfile");
  }
  return fp;
}

static void write_all_or_die(FILE *fp, const void *buf, size_t len) {
  write_exact(fp, buf, len, "write temp");
  if (fflush(fp) != 0) {
    fail_errno("flush temp");
  }
  rewind(fp);
}

static void selftest_v1(void) {
  static const char plaintext[] = "vaultcrypt self-test payload\nline2\n";
  static const char passphrase[] = "correct horse battery staple selftest";
  VaultHeaderV1 hdr;
  uint8_t header_bytes[V1_HEADER_LEN];
  uint8_t enc_key[PAYLOAD_ENC_KEY_LEN];
  uint8_t mac_key[PAYLOAD_MAC_KEY_LEN];
  uint8_t cipherbuf[sizeof(plaintext) + 32];
  uint8_t plainbuf[sizeof(plaintext) + 32];
  uint8_t tag[TAG_LEN];
  uint8_t actual_tag[TAG_LEN];
  CCHmacContext hmac;
  CCCryptorRef enc = NULL;
  CCCryptorRef dec = NULL;
  size_t cipher_len = 0;
  size_t plain_len = 0;
  FILE *cipher = NULL;
  uint8_t tampered_byte;

  fill_header_v1(&hdr, DEFAULT_ITERATIONS);
  serialize_header_v1(&hdr, header_bytes);
  derive_legacy_keys(passphrase, hdr.salt, hdr.iterations, enc_key, mac_key);

  enc = create_ctr_cryptor(kCCEncrypt, enc_key, hdr.iv);
  if (CCCryptorUpdate(enc, plaintext, sizeof(plaintext), cipherbuf, sizeof(cipherbuf), &cipher_len) != kCCSuccess) {
    fail_msg("selftest v1 encryption failed");
  }
  CCCryptorRelease(enc);

  CCHmacInit(&hmac, kCCHmacAlgSHA256, mac_key, PAYLOAD_MAC_KEY_LEN);
  CCHmacUpdate(&hmac, header_bytes, sizeof(header_bytes));
  CCHmacUpdate(&hmac, cipherbuf, cipher_len);
  CCHmacFinal(&hmac, tag);

  CCHmacInit(&hmac, kCCHmacAlgSHA256, mac_key, PAYLOAD_MAC_KEY_LEN);
  CCHmacUpdate(&hmac, header_bytes, sizeof(header_bytes));
  CCHmacUpdate(&hmac, cipherbuf, cipher_len);
  CCHmacFinal(&hmac, actual_tag);
  if (!constant_time_eq(tag, actual_tag, TAG_LEN)) {
    fail_msg("selftest v1 tag mismatch");
  }

  dec = create_ctr_cryptor(kCCDecrypt, enc_key, hdr.iv);
  if (CCCryptorUpdate(dec, cipherbuf, cipher_len, plainbuf, sizeof(plainbuf), &plain_len) != kCCSuccess) {
    fail_msg("selftest v1 decryption failed");
  }
  CCCryptorRelease(dec);
  if (plain_len != sizeof(plaintext) || memcmp(plainbuf, plaintext, sizeof(plaintext)) != 0) {
    fail_msg("selftest v1 round-trip mismatch");
  }

  derive_legacy_keys("wrong password", hdr.salt, hdr.iterations, enc_key, mac_key);
  CCHmacInit(&hmac, kCCHmacAlgSHA256, mac_key, PAYLOAD_MAC_KEY_LEN);
  CCHmacUpdate(&hmac, header_bytes, sizeof(header_bytes));
  CCHmacUpdate(&hmac, cipherbuf, cipher_len);
  CCHmacFinal(&hmac, actual_tag);
  if (constant_time_eq(tag, actual_tag, TAG_LEN)) {
    fail_msg("selftest v1 wrong-password case did not fail");
  }

  cipher = tmpfile_or_die();
  write_all_or_die(cipher, cipherbuf, cipher_len);
  tampered_byte = (uint8_t)(cipherbuf[0] ^ 0x01u);
  rewind(cipher);
  write_exact(cipher, &tampered_byte, 1, "tamper write");
  fflush(cipher);
  rewind(cipher);
  read_exact(cipher, cipherbuf, cipher_len, "tamper read");
  fclose(cipher);

  derive_legacy_keys(passphrase, hdr.salt, hdr.iterations, enc_key, mac_key);
  CCHmacInit(&hmac, kCCHmacAlgSHA256, mac_key, PAYLOAD_MAC_KEY_LEN);
  CCHmacUpdate(&hmac, header_bytes, sizeof(header_bytes));
  CCHmacUpdate(&hmac, cipherbuf, cipher_len);
  CCHmacFinal(&hmac, actual_tag);
  if (constant_time_eq(tag, actual_tag, TAG_LEN)) {
    fail_msg("selftest v1 tamper detection failed");
  }

  secure_release_buffer(enc_key, sizeof(enc_key));
  secure_release_buffer(mac_key, sizeof(mac_key));
}

static void selftest_v2(void) {
  static const char plaintext[] = "vaultcrypt v2 self-test payload\nline2\n";
  static const char passphrase[] = "correct horse battery staple selftest";
  uint8_t recovery_key[RECOVERY_KEY_LEN];
  VaultHeaderV2 hdr;
  VaultKeySlotV2 slots[MAX_KEY_SLOTS];
  uint8_t header_bytes[V2_FIXED_HEADER_LEN];
  uint8_t passphrase_key[MASTER_KEY_LEN];
  uint8_t wrong_passphrase_key[MASTER_KEY_LEN];
  uint8_t file_key[FILE_KEY_LEN];
  uint8_t unwrapped_key[FILE_KEY_LEN];
  uint8_t cipherbuf[sizeof(plaintext) + 32];
  uint8_t plainbuf[sizeof(plaintext) + 32];
  uint8_t tag[TAG_LEN];
  uint8_t actual_tag[TAG_LEN];
  CCHmacContext hmac;
  CCCryptorRef enc = NULL;
  CCCryptorRef dec = NULL;
  size_t cipher_len = 0;
  size_t plain_len = 0;
  size_t unwrapped_len = FILE_KEY_LEN;
  FILE *cipher = NULL;
  uint8_t tampered_byte;

  memset(slots, 0, sizeof(slots));
  fill_header_v2(&hdr, DEFAULT_ITERATIONS);
  derive_master_key(passphrase, hdr.salt, hdr.iterations, passphrase_key);
  random_bytes(recovery_key, sizeof(recovery_key));
  random_bytes(file_key, sizeof(file_key));
  wrap_file_key_for_slot(passphrase_key, SLOT_TYPE_PASSPHRASE, file_key, &slots[0]);
  wrap_file_key_for_slot(recovery_key, SLOT_TYPE_RECOVERY, file_key, &slots[1]);
  set_slot_count(&hdr, 2u);
  serialize_header_v2(&hdr, header_bytes);
  unwrap_file_key_with_key(passphrase_key, &slots[0], unwrapped_key);
  if (memcmp(file_key, unwrapped_key, sizeof(file_key)) != 0) {
    fail_msg("selftest v2 passphrase unwrap mismatch");
  }
  unwrap_file_key_with_key(recovery_key, &slots[1], unwrapped_key);
  if (memcmp(file_key, unwrapped_key, sizeof(file_key)) != 0) {
    fail_msg("selftest v2 recovery unwrap mismatch");
  }

  enc = create_ctr_cryptor(kCCEncrypt, file_key, hdr.iv);
  if (CCCryptorUpdate(enc, plaintext, sizeof(plaintext), cipherbuf, sizeof(cipherbuf), &cipher_len) != kCCSuccess) {
    fail_msg("selftest v2 encryption failed");
  }
  CCCryptorRelease(enc);

  CCHmacInit(&hmac, kCCHmacAlgSHA256, file_key + PAYLOAD_ENC_KEY_LEN, PAYLOAD_MAC_KEY_LEN);
  CCHmacUpdate(&hmac, header_bytes, sizeof(header_bytes));
  hmac_update_v2_slots(&hmac, slots, hdr.slot_count);
  CCHmacUpdate(&hmac, cipherbuf, cipher_len);
  CCHmacFinal(&hmac, tag);

  CCHmacInit(&hmac, kCCHmacAlgSHA256, file_key + PAYLOAD_ENC_KEY_LEN, PAYLOAD_MAC_KEY_LEN);
  CCHmacUpdate(&hmac, header_bytes, sizeof(header_bytes));
  hmac_update_v2_slots(&hmac, slots, hdr.slot_count);
  CCHmacUpdate(&hmac, cipherbuf, cipher_len);
  CCHmacFinal(&hmac, actual_tag);
  if (!constant_time_eq(tag, actual_tag, TAG_LEN)) {
    fail_msg("selftest v2 tag mismatch");
  }

  dec = create_ctr_cryptor(kCCDecrypt, file_key, hdr.iv);
  if (CCCryptorUpdate(dec, cipherbuf, cipher_len, plainbuf, sizeof(plainbuf), &plain_len) != kCCSuccess) {
    fail_msg("selftest v2 decryption failed");
  }
  CCCryptorRelease(dec);
  if (plain_len != sizeof(plaintext) || memcmp(plainbuf, plaintext, sizeof(plaintext)) != 0) {
    fail_msg("selftest v2 round-trip mismatch");
  }

  derive_master_key("wrong password", hdr.salt, hdr.iterations, wrong_passphrase_key);
  if (CCSymmetricKeyUnwrap(kCCWRAPAES,
                           CCrfc3394_iv,
                           CCrfc3394_ivLen,
                           wrong_passphrase_key,
                           MASTER_KEY_LEN,
                           slots[0].wrapped_key,
                           slots[0].wrapped_key_len,
                           unwrapped_key,
                           &unwrapped_len) == kCCSuccess) {
    fail_msg("selftest v2 wrong-password unwrap did not fail");
  }

  cipher = tmpfile_or_die();
  write_all_or_die(cipher, cipherbuf, cipher_len);
  tampered_byte = (uint8_t)(cipherbuf[0] ^ 0x01u);
  rewind(cipher);
  write_exact(cipher, &tampered_byte, 1, "tamper write");
  fflush(cipher);
  rewind(cipher);
  read_exact(cipher, cipherbuf, cipher_len, "tamper read");
  fclose(cipher);

  CCHmacInit(&hmac, kCCHmacAlgSHA256, file_key + PAYLOAD_ENC_KEY_LEN, PAYLOAD_MAC_KEY_LEN);
  CCHmacUpdate(&hmac, header_bytes, sizeof(header_bytes));
  hmac_update_v2_slots(&hmac, slots, hdr.slot_count);
  CCHmacUpdate(&hmac, cipherbuf, cipher_len);
  CCHmacFinal(&hmac, actual_tag);
  if (constant_time_eq(tag, actual_tag, TAG_LEN)) {
    fail_msg("selftest v2 tamper detection failed");
  }

  secure_release_buffer(passphrase_key, sizeof(passphrase_key));
  secure_release_buffer(wrong_passphrase_key, sizeof(wrong_passphrase_key));
  secure_release_buffer(recovery_key, sizeof(recovery_key));
  secure_release_buffer(file_key, sizeof(file_key));
  secure_release_buffer(unwrapped_key, sizeof(unwrapped_key));
}

static void selftest_v3(void) {
  static const char plaintext[] = "vaultcrypt v3 streamed self-test payload";
  static const char passphrase[] = "correct horse battery staple selftest";
  VaultHeaderV3 hdr;
  VaultKeySlotV2 slots[MAX_KEY_SLOTS];
  uint8_t header_bytes[V3_FIXED_HEADER_LEN];
  uint8_t header_tag[TAG_LEN];
  uint8_t actual_header_tag[TAG_LEN];
  uint8_t chunk_tag[TAG_LEN];
  uint8_t actual_chunk_tag[TAG_LEN];
  uint8_t passphrase_key[MASTER_KEY_LEN];
  uint8_t recovery_key[RECOVERY_KEY_LEN];
  uint8_t file_key[FILE_KEY_LEN];
  uint8_t chunk_iv[IV_LEN];
  uint8_t cipherbuf[sizeof(plaintext) + 32];
  uint8_t plainbuf[sizeof(plaintext) + 32];
  size_t offset = 0;
  size_t plain_offset = 0;
  uint64_t chunk_index = 0;

  memset(slots, 0, sizeof(slots));
  memset(cipherbuf, 0, sizeof(cipherbuf));
  memset(plainbuf, 0, sizeof(plainbuf));

  fill_header_v3(&hdr, DEFAULT_ITERATIONS);
  hdr.chunk_size = 8u;
  derive_master_key(passphrase, hdr.salt, hdr.iterations, passphrase_key);
  random_bytes(recovery_key, sizeof(recovery_key));
  random_bytes(file_key, sizeof(file_key));
  wrap_file_key_for_slot(passphrase_key, SLOT_TYPE_PASSPHRASE, file_key, &slots[0]);
  wrap_file_key_for_slot(recovery_key, SLOT_TYPE_RECOVERY, file_key, &slots[1]);
  set_slot_count_v3(&hdr, 2u);
  serialize_header_v3(&hdr, header_bytes);
  compute_v3_header_tag(file_key + PAYLOAD_ENC_KEY_LEN, header_bytes, slots, hdr.slot_count, header_tag);
  compute_v3_header_tag(file_key + PAYLOAD_ENC_KEY_LEN, header_bytes, slots, hdr.slot_count, actual_header_tag);
  if (!constant_time_eq(header_tag, actual_header_tag, TAG_LEN)) {
    fail_msg("selftest v3 header tag mismatch");
  }

  while (offset < sizeof(plaintext)) {
    size_t chunk_len = sizeof(plaintext) - offset;
    uint32_t flags = 0;
    CCCryptorRef cryptor;
    CCCryptorStatus status;
    size_t produced = 0;

    if (chunk_len > hdr.chunk_size) {
      chunk_len = hdr.chunk_size;
    }
    if (offset + chunk_len == sizeof(plaintext)) {
      flags = V3_CHUNK_FINAL_FLAG;
    }

    derive_chunk_iv(hdr.iv, chunk_index, chunk_iv);
    cryptor = create_ctr_cryptor(kCCEncrypt, file_key, chunk_iv);
    status = CCCryptorUpdate(cryptor,
                             plaintext + offset,
                             chunk_len,
                             cipherbuf + offset,
                             sizeof(cipherbuf) - offset,
                             &produced);
    CCCryptorRelease(cryptor);
    if (status != kCCSuccess || produced != chunk_len) {
      fail_msg("selftest v3 encryption failed");
    }

    compute_v3_chunk_tag(file_key + PAYLOAD_ENC_KEY_LEN,
                         hdr.iv,
                         chunk_index,
                         flags,
                         cipherbuf + offset,
                         (uint32_t)chunk_len,
                         chunk_tag);
    compute_v3_chunk_tag(file_key + PAYLOAD_ENC_KEY_LEN,
                         hdr.iv,
                         chunk_index,
                         flags,
                         cipherbuf + offset,
                         (uint32_t)chunk_len,
                         actual_chunk_tag);
    if (!constant_time_eq(chunk_tag, actual_chunk_tag, TAG_LEN)) {
      fail_msg("selftest v3 chunk tag mismatch");
    }

    cryptor = create_ctr_cryptor(kCCDecrypt, file_key, chunk_iv);
    status = CCCryptorUpdate(cryptor,
                             cipherbuf + offset,
                             chunk_len,
                             plainbuf + plain_offset,
                             sizeof(plainbuf) - plain_offset,
                             &produced);
    CCCryptorRelease(cryptor);
    if (status != kCCSuccess || produced != chunk_len) {
      fail_msg("selftest v3 decryption failed");
    }

    plain_offset += produced;
    offset += chunk_len;
    chunk_index++;
  }

  if (plain_offset != sizeof(plaintext) || memcmp(plainbuf, plaintext, sizeof(plaintext)) != 0) {
    fail_msg("selftest v3 round-trip mismatch");
  }

  cipherbuf[0] ^= 0x01u;
  compute_v3_chunk_tag(file_key + PAYLOAD_ENC_KEY_LEN,
                       hdr.iv,
                       0u,
                       0u,
                       cipherbuf,
                       hdr.chunk_size,
                       actual_chunk_tag);
  cipherbuf[0] ^= 0x01u;
  compute_v3_chunk_tag(file_key + PAYLOAD_ENC_KEY_LEN,
                       hdr.iv,
                       0u,
                       0u,
                       cipherbuf,
                       hdr.chunk_size,
                       chunk_tag);
  if (constant_time_eq(chunk_tag, actual_chunk_tag, TAG_LEN)) {
    fail_msg("selftest v3 tamper detection failed");
  }

  secure_release_buffer(passphrase_key, sizeof(passphrase_key));
  secure_release_buffer(recovery_key, sizeof(recovery_key));
  secure_release_buffer(file_key, sizeof(file_key));
}

static void selftest_command(void) {
  selftest_v1();
  selftest_v2();
  selftest_v3();
  puts("selftest: ok");
}

int main(int argc, char **argv) {
  const char *command = NULL;
  const char *input_path = NULL;
  const char *output_path = NULL;
  uint32_t iterations = DEFAULT_ITERATIONS;
  int iterations_explicit = 0;
  Options opts = {0, 0, 1, 0, NULL, NULL};
  int i;
  char *end = NULL;
  unsigned long parsed;

  if (argc < 2) {
    usage(stderr, 2);
  }

  if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "help") == 0) {
    usage(stdout, 0);
  }

  command = argv[1];
  for (i = 2; i < argc; ++i) {
    if (strcmp(argv[i], "-i") == 0) {
      if (++i >= argc) {
        usage(stderr, 2);
      }
      input_path = argv[i];
    } else if (strcmp(argv[i], "-o") == 0) {
      if (++i >= argc) {
        usage(stderr, 2);
      }
      output_path = argv[i];
    } else if (strcmp(argv[i], "-n") == 0) {
      if (++i >= argc) {
        usage(stderr, 2);
      }
      errno = 0;
      end = NULL;
      parsed = strtoul(argv[i], &end, 10);
      if (errno != 0 || end == argv[i] || *end != '\0' || parsed > UINT32_MAX) {
        fail_msg("invalid iteration count");
      }
      iterations = (uint32_t)parsed;
      iterations_explicit = 1;
    } else if (strcmp(argv[i], "-f") == 0) {
      opts.force = 1;
    } else if (strcmp(argv[i], "--stdout") == 0) {
      opts.allow_stdout = 1;
      output_path = "-";
    } else if (strcmp(argv[i], "--json") == 0) {
      opts.info_json = 1;
    } else if (strcmp(argv[i], "--recovery-key") == 0) {
      if (++i >= argc) {
        usage(stderr, 2);
      }
      opts.recovery_key_path = argv[i];
    } else if (strcmp(argv[i], "--recovery-key-out") == 0) {
      if (++i >= argc) {
        usage(stderr, 2);
      }
      opts.recovery_key_out_path = argv[i];
    } else if (strcmp(argv[i], "--no-tty") == 0) {
      opts.require_tty = 0;
    } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      usage(stdout, 0);
    } else {
      usage(stderr, 2);
    }
  }

  if (strcmp(command, "enc") == 0) {
    encrypt_command(input_path, output_path, iterations, &opts);
    return 0;
  }
  if (strcmp(command, "dec") == 0) {
    if (output_path != NULL && strcmp(output_path, "-") == 0) {
      opts.allow_stdout = 1;
    }
    decrypt_command(input_path, output_path, &opts);
    return 0;
  }
  if (strcmp(command, "rewrap") == 0) {
    rewrap_command(input_path, output_path, iterations, iterations_explicit, &opts);
    return 0;
  }
  if (strcmp(command, "info") == 0) {
    info_command(input_path, &opts);
    return 0;
  }
  if (strcmp(command, "selftest") == 0) {
    selftest_command();
    return 0;
  }

  usage(stderr, 2);
}
