#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <CommonCrypto/CommonRandom.h>
#include <dirent.h>
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

#include "vaultcrypt_embedded_source.h"

/*
 * vaultcrypt
 *
 * Minimal VLTENC03 format (legacy, all integers big-endian):
 *   magic[8]      = "VLTENC03"
 *   version[4]    = 3
 *   kdf_id[4]     = 1   (PBKDF2-HMAC-SHA256)
 *   cipher_id[4]  = 1   (AES-256-CTR)
 *   mac_id[4]     = 1   (HMAC-SHA256 over header || ciphertext)
 *   iterations[4] = PBKDF2 iteration count
 *   salt_len[4]   = 32
 *   iv_len[4]     = 16
 *   reserved[4]   = 0
 *   salt[32]
 *   iv[16]
 *   ciphertext[n]
 *   tag[32]
 *
 * Preferred VLTENC04 format (self-describing text header):
 *   VLTENC04\n
 *   version: 4\n
 *   kdf_id: 1\n
 *   kdf: PBKDF2-HMAC-SHA256\n
 *   cipher_id: 1\n
 *   cipher: AES-256-CTR\n
 *   mac_id: 1\n
 *   mac: HMAC-SHA256 (header || ciphertext)\n
 *   iterations: <decimal>\n
 *   salt_len: 32\n
 *   iv_len: 16\n
 *   reserved: 0\n
 *   salt_hex: <64 hex chars>\n
 *   iv_hex: <32 hex chars>\n
 *   recovery_source_name: vaultcrypt.c\n
 *   recovery_source_encoding: base64\n
 *   recovery_source_bytes: <decimal>\n
 *   recovery_source_base64_len: <decimal>\n
 *   recovery_end_marker: ===END-RECOVERY===\n
 *   recovery_layout: after this blank line, read recovery_source_base64_len bytes,\n
 *                    then confirm the next line is recovery_end_marker,\n
 *                    then skip one blank line; ciphertext starts after that.\n
 *   recovery_decode_hint: base64 -d vaultcrypt.c.b64 > vaultcrypt.c\n
 *   \n
 *   recovery_source_base64[recovery_source_base64_len]
 *   ===END-RECOVERY===\n
 *   \n
 *   ciphertext[n]
 *   tag[32]
 *
 * Key derivation:
 *   passphrase -> PBKDF2-HMAC-SHA256 -> 64 bytes
 *   first 32 bytes  = AES-256-CTR key
 *   last 32 bytes   = HMAC-SHA256 key
 */

#define MAGIC_V3 "VLTENC03"
#define MAGIC_V4 "VLTENC04"
#define MAGIC_LEN 8u

#define VERSION_V3 3u
#define VERSION_V4 4u

#define KDF_ID_PBKDF2_SHA256 1u
#define CIPHER_ID_AES256_CTR 1u
#define MAC_ID_HMAC_SHA256_ETM 1u

#define SALT_LEN 32u
#define IV_LEN 16u
#define ENC_KEY_LEN 32u
#define MAC_KEY_LEN 32u
#define DERIVED_KEY_LEN (ENC_KEY_LEN + MAC_KEY_LEN)
#define TAG_LEN 32u
#define HEADER_RESERVED 0u
#define V3_HEADER_LEN (MAGIC_LEN + (8u * 4u) + SALT_LEN + IV_LEN)
#define MAX_HEADER_LEN 4096u
#define RECOVERY_LINE_WRAP 64u
#define RECOVERY_SOURCE_NAME "vaultcrypt.c"
#define RECOVERY_SOURCE_ENCODING "base64"
#define RECOVERY_END_MARKER "===END-RECOVERY==="
#define RECOVERY_MARKER_SUFFIX RECOVERY_END_MARKER "\n\n"
#define DEFAULT_ITERATIONS 600000u
#define MIN_ITERATIONS 100000u
#define IO_CHUNK_SIZE 65536u
#define PASS_MAX 1024u
#define SHA256_HEX_LEN 64u
#define NAME_KEY_LEN 32u
#define MANIFEST_FILENAME ".vaultcrypt-manifest.vlt"
#define NAME_KEY_CONTEXT "vaultcrypt-flat-path-v1"

typedef struct {
  char *rel_path;
  uint64_t size;
  char sha256_hex[SHA256_HEX_LEN + 1u];
  int seen;
} ManifestEntry;

typedef struct {
  ManifestEntry *items;
  size_t len;
  size_t cap;
} Manifest;

typedef enum {
  FORMAT_UNKNOWN = 0,
  FORMAT_V3 = 3,
  FORMAT_V4 = 4
} VaultFormat;

typedef struct {
  int force;
  int allow_stdout;
  int require_tty;
  int info_json;
  const char *keychain_service;
  const char *keychain_account;
} Options;

typedef struct {
  uint32_t version;
  uint32_t kdf_id;
  uint32_t cipher_id;
  uint32_t mac_id;
  uint32_t iterations;
  uint32_t salt_len;
  uint32_t iv_len;
  uint32_t reserved;
  uint8_t salt[SALT_LEN];
  uint8_t iv[IV_LEN];
} VaultHeader;

typedef struct {
  VaultHeader hdr;
  uint32_t recovery_source_bytes;
  uint32_t recovery_source_base64_len;
} VaultHeaderV4Info;

static FILE *open_input_file(const char *path);
static char *parent_dirname(const char *path);

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
          "  vaultcrypt dec -i INPUT [-o OUTPUT|-] [-f] [--stdout]\n"
          "  vaultcrypt info -i INPUT [--json]\n"
          "  vaultcrypt syncdir -i SOURCE_DIR -o VAULT_DIR [-n ITERATIONS]\n"
          "  vaultcrypt restoredir -i VAULT_DIR -o OUTPUT_DIR\n"
          "  vaultcrypt selftest\n"
          "\n"
          "Notes:\n"
          "  - macOS only: uses built-in CommonCrypto.\n"
          "  - enc writes VLTENC04 files with a readable text header.\n"
          "  - dec and info read both VLTENC03 and VLTENC04 files.\n"
          "  - enc and dec use passphrase-derived AES-256-CTR + HMAC-SHA256.\n"
          "  - enc prompts twice for a passphrase.\n"
          "  - dec authenticates the full ciphertext before releasing plaintext.\n"
          "  - enc OUTPUT defaults to INPUT.vlt.\n"
          "  - dec requires -o PATH or explicit stdout with -o - or --stdout.\n"
          "  - syncdir keeps an encrypted manifest in the vault directory.\n"
          "  - syncdir stores ciphertext as flat opaque filenames; plaintext paths only exist inside the encrypted manifest.\n"
          "  - restoredir rebuilds the original plaintext filenames and directory tree from the manifest.\n"
          "  - use --passphrase-keychain-service SERVICE to load the passphrase from macOS Keychain.\n"
          "  - optional: --passphrase-keychain-account ACCOUNT (defaults to $USER).\n");
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

static void fail_path(const char *label, const char *path) {
  fprintf(stderr, "vaultcrypt: %s: %s\n", label, path);
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

static const char *kdf_name(uint32_t id) {
  switch (id) {
    case KDF_ID_PBKDF2_SHA256:
      return "PBKDF2-HMAC-SHA256";
    default:
      return "unknown";
  }
}

static const char *cipher_name(uint32_t id) {
  switch (id) {
    case CIPHER_ID_AES256_CTR:
      return "AES-256-CTR";
    default:
      return "unknown";
  }
}

static const char *mac_name(uint32_t id) {
  switch (id) {
    case MAC_ID_HMAC_SHA256_ETM:
      return "HMAC-SHA256 (header || ciphertext)";
    default:
      return "unknown";
  }
}

static void hex_encode(const uint8_t *src, size_t len, char *dst, size_t dst_len) {
  static const char digits[] = "0123456789abcdef";
  size_t i;

  if (dst_len < (len * 2u) + 1u) {
    fail_msg("hex buffer too small");
  }

  for (i = 0; i < len; ++i) {
    dst[i * 2u] = digits[src[i] >> 4];
    dst[i * 2u + 1u] = digits[src[i] & 0x0fu];
  }
  dst[len * 2u] = '\0';
}

static int hex_value(int ch) {
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  }
  if (ch >= 'a' && ch <= 'f') {
    return 10 + (ch - 'a');
  }
  if (ch >= 'A' && ch <= 'F') {
    return 10 + (ch - 'A');
  }
  return -1;
}

static void hex_decode_exact(const char *src, uint8_t *dst, size_t dst_len, const char *label) {
  size_t i;

  if (strlen(src) != dst_len * 2u) {
    fail_msg(label);
  }

  for (i = 0; i < dst_len; ++i) {
    int hi = hex_value((unsigned char)src[i * 2u]);
    int lo = hex_value((unsigned char)src[i * 2u + 1u]);

    if (hi < 0 || lo < 0) {
      fail_msg(label);
    }
    dst[i] = (uint8_t)((hi << 4) | lo);
  }
}

static uint32_t parse_u32_strict(const char *src, const char *label) {
  char *end = NULL;
  unsigned long parsed;

  errno = 0;
  parsed = strtoul(src, &end, 10);
  if (errno != 0 || end == src || *end != '\0' || parsed > UINT32_MAX) {
    fail_msg(label);
  }
  return (uint32_t)parsed;
}

static uint8_t *load_recovery_source(size_t *len_out) {
  uint8_t *copy;

  if (vaultcrypt_c_len == 0u) {
    fail_msg("embedded recovery source is missing; rebuild vaultcrypt");
  }

  copy = (uint8_t *)malloc((size_t)vaultcrypt_c_len);
  if (copy == NULL) {
    fail_msg("out of memory");
  }
  memcpy(copy, vaultcrypt_c, (size_t)vaultcrypt_c_len);
  *len_out = (size_t)vaultcrypt_c_len;
  return copy;
}

static uint8_t *base64_encode_wrapped(const uint8_t *src, size_t len, size_t *out_len) {
  static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t raw_len = ((len + 2u) / 3u) * 4u;
  size_t line_breaks = raw_len == 0u ? 1u : (raw_len + RECOVERY_LINE_WRAP - 1u) / RECOVERY_LINE_WRAP;
  size_t total_len = raw_len + line_breaks;
  uint8_t *out = (uint8_t *)malloc(total_len + 1u);
  size_t src_i = 0;
  size_t line_count = 0;
  size_t out_i = 0;

  if (out == NULL) {
    fail_msg("out of memory");
  }

  while (src_i < len) {
    uint32_t chunk = 0;
    size_t remain = len - src_i;
    size_t take = remain >= 3u ? 3u : remain;
    size_t j;

    for (j = 0; j < take; ++j) {
      chunk |= (uint32_t)src[src_i + j] << (16u - (8u * j));
    }

    out[out_i++] = (uint8_t)table[(chunk >> 18) & 0x3fu];
    out[out_i++] = (uint8_t)table[(chunk >> 12) & 0x3fu];
    out[out_i++] = (uint8_t)(take > 1u ? table[(chunk >> 6) & 0x3fu] : '=');
    out[out_i++] = (uint8_t)(take > 2u ? table[chunk & 0x3fu] : '=');
    src_i += take;
    line_count += 4u;

    if (line_count == RECOVERY_LINE_WRAP && src_i < len) {
      out[out_i++] = '\n';
      line_count = 0;
    }
  }

  out[out_i++] = '\n';
  out[out_i] = '\0';
  *out_len = out_i;
  return out;
}

static void print_hex_ascii_line(const uint8_t *src, size_t offset, size_t count) {
  size_t i;

  printf("%04zx: ", offset);
  for (i = 0; i < 16u; ++i) {
    if (i < count) {
      printf("%02x ", src[i]);
    } else {
      printf("   ");
    }
  }

  printf(" |");
  for (i = 0; i < count; ++i) {
    unsigned char ch = src[i];
    if (ch >= 32u && ch <= 126u) {
      putchar((int)ch);
    } else {
      putchar('.');
    }
  }
  for (; i < 16u; ++i) {
    putchar(' ');
  }
  printf("|\n");
}

static void print_header_dump(const uint8_t *src, size_t len) {
  size_t offset = 0;

  while (offset < len) {
    size_t remaining = len - offset;
    size_t count = remaining < 16u ? remaining : 16u;
    print_hex_ascii_line(src + offset, offset, count);
    offset += count;
  }
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
  char *dst = (char *)malloc(len + 1u);

  if (dst == NULL) {
    fail_msg("out of memory");
  }

  memcpy(dst, src, len + 1u);
  return dst;
}

static char *xstrndup_local(const char *src, size_t len) {
  char *dst = (char *)malloc(len + 1u);

  if (dst == NULL) {
    fail_msg("out of memory");
  }
  memcpy(dst, src, len);
  dst[len] = '\0';
  return dst;
}

static bool path_exists(const char *path) {
  struct stat st;
  return stat(path, &st) == 0;
}

static void require_directory(const char *path, const char *label) {
  struct stat st;

  if (stat(path, &st) != 0) {
    fail_errno(path);
  }
  if (!S_ISDIR(st.st_mode)) {
    fail_path(label, path);
  }
}

static void ensure_dir_recursive(const char *path) {
  char *copy;
  size_t i;

  if (path == NULL || path[0] == '\0') {
    return;
  }

  copy = xstrdup(path);
  for (i = 1; copy[i] != '\0'; ++i) {
    if (copy[i] == '/') {
      copy[i] = '\0';
      if (copy[0] != '\0' && mkdir(copy, 0700) != 0 && errno != EEXIST) {
        const int saved_errno = errno;
        fprintf(stderr, "vaultcrypt: mkdir failed: %s: %s\n", copy, strerror(saved_errno));
        free(copy);
        exit(1);
      }
      copy[i] = '/';
    }
  }
  if (mkdir(copy, 0700) != 0 && errno != EEXIST) {
    const int saved_errno = errno;
    fprintf(stderr, "vaultcrypt: mkdir failed: %s: %s\n", copy, strerror(saved_errno));
    free(copy);
    exit(1);
  }
  free(copy);
}

static void ensure_parent_dir(const char *path) {
  char *parent = parent_dirname(path);
  ensure_dir_recursive(parent);
  free(parent);
}

static void remove_empty_parent_dirs_until(const char *path, const char *stop_dir) {
  char *dir = parent_dirname(path);
  size_t stop_len = strlen(stop_dir);

  while (dir[0] != '\0' &&
         strcmp(dir, ".") != 0 &&
         strcmp(dir, "/") != 0 &&
         strncmp(dir, stop_dir, stop_len) == 0 &&
         (dir[stop_len] == '\0' || dir[stop_len] == '/')) {
    if (strcmp(dir, stop_dir) == 0) {
      break;
    }
    if (rmdir(dir) != 0) {
      if (errno == ENOTEMPTY || errno == EEXIST || errno == ENOENT) {
        break;
      }
      free(dir);
      fail_errno("rmdir");
    }
    {
      char *parent = parent_dirname(dir);
      free(dir);
      dir = parent;
    }
  }
  free(dir);
}

static char *parent_dirname(const char *path) {
  const char *slash = strrchr(path, '/');

  if (slash == NULL) {
    return xstrdup(".");
  }
  if (slash == path) {
    return xstrdup("/");
  }
  return xstrndup_local(path, (size_t)(slash - path));
}

static char *join_path(const char *base, const char *suffix) {
  size_t base_len = strlen(base);
  size_t suffix_len = strlen(suffix);
  int need_slash = base_len > 0u && base[base_len - 1u] != '/';
  size_t len = base_len + (size_t)need_slash + suffix_len + 1u;
  char *out = (char *)malloc(len);

  if (out == NULL) {
    fail_msg("out of memory");
  }
  snprintf(out, len, "%s%s%s", base, need_slash ? "/" : "", suffix);
  return out;
}

static char *manifest_path(const char *vault_dir) {
  return join_path(vault_dir, MANIFEST_FILENAME);
}

static void derive_name_key(const char *passphrase, uint8_t name_key[NAME_KEY_LEN]) {
  CCHmac(kCCHmacAlgSHA256,
         passphrase,
         strlen(passphrase),
         NAME_KEY_CONTEXT,
         strlen(NAME_KEY_CONTEXT),
         name_key);
}

static char *opaque_vault_filename(const char *rel_path, const uint8_t name_key[NAME_KEY_LEN]) {
  uint8_t digest[CC_SHA256_DIGEST_LENGTH];
  char digest_hex[(CC_SHA256_DIGEST_LENGTH * 2u) + 1u];
  const char *suffix = ".vlt";
  size_t len;
  char *out;

  CCHmac(kCCHmacAlgSHA256,
         name_key,
         NAME_KEY_LEN,
         rel_path,
         strlen(rel_path),
         digest);
  hex_encode(digest, sizeof(digest), digest_hex, sizeof(digest_hex));
  len = strlen(digest_hex) + strlen(suffix) + 1u;
  out = (char *)malloc(len);
  if (out == NULL) {
    fail_msg("out of memory");
  }
  snprintf(out, len, "%s%s", digest_hex, suffix);
  return out;
}

static char *vault_file_path(const char *vault_dir,
                             const char *rel_path,
                             const uint8_t name_key[NAME_KEY_LEN]) {
  char *basename = opaque_vault_filename(rel_path, name_key);
  char *out = join_path(vault_dir, basename);

  free(basename);
  return out;
}

static char *legacy_vault_file_path(const char *vault_dir, const char *rel_path) {
  const char *suffix = ".vlt";
  char *joined = join_path(vault_dir, rel_path);
  size_t len = strlen(joined) + strlen(suffix) + 1u;
  char *out = (char *)malloc(len);

  if (out == NULL) {
    free(joined);
    fail_msg("out of memory");
  }
  snprintf(out, len, "%s%s", joined, suffix);
  free(joined);
  return out;
}

static void remove_legacy_cipher_if_present(const char *vault_dir,
                                            const char *rel_path,
                                            const char *current_cipher_path) {
  char *legacy_path = legacy_vault_file_path(vault_dir, rel_path);

  if (strcmp(legacy_path, current_cipher_path) != 0 && path_exists(legacy_path)) {
    if (unlink(legacy_path) != 0) {
      free(legacy_path);
      fail_errno("unlink legacy ciphertext");
    }
    remove_empty_parent_dirs_until(legacy_path, vault_dir);
  }
  free(legacy_path);
}

static char *restore_cipher_path(const char *vault_dir,
                                 const char *rel_path,
                                 const uint8_t name_key[NAME_KEY_LEN]) {
  char *current_path = vault_file_path(vault_dir, rel_path, name_key);

  if (path_exists(current_path)) {
    return current_path;
  }

  free(current_path);
  return legacy_vault_file_path(vault_dir, rel_path);
}

static void sha256_file_hex(const char *path, char out_hex[SHA256_HEX_LEN + 1u], uint64_t *size_out) {
  FILE *fp = open_input_file(path);
  CC_SHA256_CTX ctx;
  uint8_t buf[IO_CHUNK_SIZE];
  uint8_t digest[CC_SHA256_DIGEST_LENGTH];
  uint64_t total = 0;
  size_t nread;

  if (CC_SHA256_Init(&ctx) != 1) {
    fclose(fp);
    fail_msg("sha256 init failed");
  }

  while ((nread = fread(buf, 1, sizeof(buf), fp)) > 0u) {
    if (CC_SHA256_Update(&ctx, buf, (CC_LONG)nread) != 1) {
      fclose(fp);
      fail_msg("sha256 update failed");
    }
    total += (uint64_t)nread;
  }
  if (ferror(fp)) {
    fclose(fp);
    fail_errno(path);
  }
  fclose(fp);

  if (CC_SHA256_Final(digest, &ctx) != 1) {
    fail_msg("sha256 final failed");
  }
  hex_encode(digest, sizeof(digest), out_hex, SHA256_HEX_LEN + 1u);
  if (size_out != NULL) {
    *size_out = total;
  }
}

static void manifest_init(Manifest *manifest) {
  manifest->items = NULL;
  manifest->len = 0u;
  manifest->cap = 0u;
}

static void manifest_free(Manifest *manifest) {
  size_t i;

  for (i = 0; i < manifest->len; ++i) {
    free(manifest->items[i].rel_path);
  }
  free(manifest->items);
  manifest->items = NULL;
  manifest->len = 0u;
  manifest->cap = 0u;
}

static ManifestEntry *manifest_find(Manifest *manifest, const char *rel_path) {
  size_t i;

  for (i = 0; i < manifest->len; ++i) {
    if (strcmp(manifest->items[i].rel_path, rel_path) == 0) {
      return &manifest->items[i];
    }
  }
  return NULL;
}

static ManifestEntry *manifest_upsert(Manifest *manifest, const char *rel_path) {
  ManifestEntry *entry = manifest_find(manifest, rel_path);

  if (entry != NULL) {
    return entry;
  }
  if (manifest->len == manifest->cap) {
    size_t new_cap = manifest->cap == 0u ? 64u : manifest->cap * 2u;
    ManifestEntry *grown =
        (ManifestEntry *)realloc(manifest->items, new_cap * sizeof(ManifestEntry));
    if (grown == NULL) {
      fail_msg("out of memory");
    }
    manifest->items = grown;
    manifest->cap = new_cap;
  }
  entry = &manifest->items[manifest->len++];
  entry->rel_path = xstrdup(rel_path);
  entry->size = 0u;
  entry->sha256_hex[0] = '\0';
  entry->seen = 0;
  return entry;
}

static void manifest_reset_seen(Manifest *manifest) {
  size_t i;

  for (i = 0; i < manifest->len; ++i) {
    manifest->items[i].seen = 0;
  }
}

static void hex_encode_string(const char *src, char **out_hex) {
  size_t len = strlen(src);
  char *hex = (char *)malloc((len * 2u) + 1u);

  if (hex == NULL) {
    fail_msg("out of memory");
  }
  hex_encode((const uint8_t *)src, len, hex, (len * 2u) + 1u);
  *out_hex = hex;
}

static char *hex_decode_string_owned(const char *src) {
  size_t src_len = strlen(src);
  char *dst;

  if ((src_len % 2u) != 0u) {
    fail_msg("manifest path encoding is invalid");
  }
  dst = (char *)malloc((src_len / 2u) + 1u);
  if (dst == NULL) {
    fail_msg("out of memory");
  }
  hex_decode_exact(src, (uint8_t *)dst, src_len / 2u, "invalid manifest path encoding");
  dst[src_len / 2u] = '\0';
  return dst;
}

static void write_manifest_plaintext(const char *path, const Manifest *manifest) {
  FILE *fp = fopen(path, "wb");
  size_t i;

  if (fp == NULL) {
    fail_errno(path);
  }
  for (i = 0; i < manifest->len; ++i) {
    char *path_hex = NULL;
    ManifestEntry *entry = &manifest->items[i];

    hex_encode_string(entry->rel_path, &path_hex);
    fprintf(fp, "%s\t%llu\t%s\n", path_hex, (unsigned long long)entry->size, entry->sha256_hex);
    free(path_hex);
    if (ferror(fp)) {
      fclose(fp);
      fail_errno(path);
    }
  }
  if (fclose(fp) != 0) {
    fail_errno(path);
  }
}

static void parse_manifest_plaintext(const char *path, Manifest *manifest) {
  FILE *fp = fopen(path, "rb");
  char *line = NULL;
  size_t cap = 0u;
  ssize_t line_len;

  if (fp == NULL) {
    fail_errno(path);
  }

  while ((line_len = getline(&line, &cap, fp)) >= 0) {
    char *path_hex;
    char *size_text;
    char *hash_text;
    char *path_value;
    ManifestEntry *entry;
    char *end = NULL;
    unsigned long long parsed_size;

    if (line_len > 0 && line[line_len - 1] == '\n') {
      line[--line_len] = '\0';
    }
    path_hex = strtok(line, "\t");
    size_text = strtok(NULL, "\t");
    hash_text = strtok(NULL, "\t");
    if (path_hex == NULL || size_text == NULL || hash_text == NULL || strtok(NULL, "\t") != NULL) {
      free(line);
      fclose(fp);
      fail_msg("manifest file is malformed");
    }
    errno = 0;
    parsed_size = strtoull(size_text, &end, 10);
    if (errno != 0 || end == size_text || *end != '\0') {
      free(line);
      fclose(fp);
      fail_msg("manifest size value is invalid");
    }
    if (strlen(hash_text) != SHA256_HEX_LEN) {
      free(line);
      fclose(fp);
      fail_msg("manifest hash value is invalid");
    }
    path_value = hex_decode_string_owned(path_hex);
    entry = manifest_upsert(manifest, path_value);
    entry->size = (uint64_t)parsed_size;
    memcpy(entry->sha256_hex, hash_text, SHA256_HEX_LEN + 1u);
    entry->seen = 0;
    free(path_value);
  }

  free(line);
  if (ferror(fp)) {
    fclose(fp);
    fail_errno(path);
  }
  fclose(fp);
}

static void lock_memory_best_effort(void *ptr, size_t len) {
  if (ptr == NULL || len == 0u) {
    return;
  }
  (void)mlock(ptr, len);
}

static void unlock_memory_best_effort(void *ptr, size_t len) {
  if (ptr == NULL || len == 0u) {
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

  len = strlen(*value) + 1u;
  secure_release_buffer(*value, len);
  free(*value);
  *value = NULL;
}

static char *default_encrypt_output(const char *input) {
  const char *suffix = ".vlt";
  size_t len = strlen(input) + strlen(suffix) + 1u;
  char *path = (char *)malloc(len);

  if (path == NULL) {
    fail_msg("out of memory");
  }

  snprintf(path, len, "%s%s", input, suffix);
  return path;
}

static char *make_temp_pattern(const char *output) {
  const char *suffix = ".tmp.XXXXXX";
  size_t len = strlen(output) + strlen(suffix) + 1u;
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

static void derive_keys(const char *passphrase,
                        const uint8_t salt[SALT_LEN],
                        uint32_t iterations,
                        uint8_t enc_key[ENC_KEY_LEN],
                        uint8_t mac_key[MAC_KEY_LEN]) {
  uint8_t derived[DERIVED_KEY_LEN];
  int rc;

  rc = CCKeyDerivationPBKDF(kCCPBKDF2,
                            passphrase,
                            strlen(passphrase),
                            salt,
                            SALT_LEN,
                            kCCPRFHmacAlgSHA256,
                            iterations,
                            derived,
                            sizeof(derived));
  if (rc != kCCSuccess) {
    fail_msg("key derivation failed");
  }

  memcpy(enc_key, derived, ENC_KEY_LEN);
  memcpy(mac_key, derived + ENC_KEY_LEN, MAC_KEY_LEN);
  secure_bzero(derived, sizeof(derived));
}

static void fill_header(VaultHeader *hdr, uint32_t iterations, uint32_t version) {
  hdr->version = version;
  hdr->kdf_id = KDF_ID_PBKDF2_SHA256;
  hdr->cipher_id = CIPHER_ID_AES256_CTR;
  hdr->mac_id = MAC_ID_HMAC_SHA256_ETM;
  hdr->iterations = iterations;
  hdr->salt_len = SALT_LEN;
  hdr->iv_len = IV_LEN;
  hdr->reserved = HEADER_RESERVED;
  random_bytes(hdr->salt, sizeof(hdr->salt));
  random_bytes(hdr->iv, sizeof(hdr->iv));
}

static void serialize_header_v3(const VaultHeader *hdr, uint8_t out[V3_HEADER_LEN]) {
  memcpy(out, MAGIC_V3, MAGIC_LEN);
  write_be32(out + 8, hdr->version);
  write_be32(out + 12, hdr->kdf_id);
  write_be32(out + 16, hdr->cipher_id);
  write_be32(out + 20, hdr->mac_id);
  write_be32(out + 24, hdr->iterations);
  write_be32(out + 28, hdr->salt_len);
  write_be32(out + 32, hdr->iv_len);
  write_be32(out + 36, hdr->reserved);
  memcpy(out + 40, hdr->salt, SALT_LEN);
  memcpy(out + 72, hdr->iv, IV_LEN);
}

static uint8_t *serialize_v4_metadata(const VaultHeaderV4Info *info, size_t *len_out) {
  char salt_hex[(SALT_LEN * 2u) + 1u];
  char iv_hex[(IV_LEN * 2u) + 1u];
  int written;
  size_t len;
  uint8_t *out;

  hex_encode(info->hdr.salt, sizeof(info->hdr.salt), salt_hex, sizeof(salt_hex));
  hex_encode(info->hdr.iv, sizeof(info->hdr.iv), iv_hex, sizeof(iv_hex));
  written = snprintf(NULL,
                     0,
                     MAGIC_V4 "\n"
                     "version: %u\n"
                     "kdf_id: %u\n"
                     "kdf: %s\n"
                     "cipher_id: %u\n"
                     "cipher: %s\n"
                     "mac_id: %u\n"
                     "mac: %s\n"
                     "iterations: %u\n"
                     "salt_len: %u\n"
                     "iv_len: %u\n"
                     "reserved: %u\n"
                     "salt_hex: %s\n"
                     "iv_hex: %s\n"
                     "recovery_source_name: %s\n"
                     "recovery_source_encoding: %s\n"
                     "recovery_source_bytes: %u\n"
                     "recovery_source_base64_len: %u\n"
                     "recovery_end_marker: %s\n"
                     "recovery_layout: after this blank line, read recovery_source_base64_len bytes, then confirm the next line is recovery_end_marker, then skip one blank line; ciphertext starts after that.\n"
                     "recovery_decode_hint: base64 -d vaultcrypt.c.b64 > vaultcrypt.c\n"
                     "\n",
                     info->hdr.version,
                     info->hdr.kdf_id,
                     kdf_name(info->hdr.kdf_id),
                     info->hdr.cipher_id,
                     cipher_name(info->hdr.cipher_id),
                     info->hdr.mac_id,
                     mac_name(info->hdr.mac_id),
                     info->hdr.iterations,
                     info->hdr.salt_len,
                     info->hdr.iv_len,
                     info->hdr.reserved,
                     salt_hex,
                     iv_hex,
                     RECOVERY_SOURCE_NAME,
                     RECOVERY_SOURCE_ENCODING,
                     info->recovery_source_bytes,
                     info->recovery_source_base64_len,
                     RECOVERY_END_MARKER);
  if (written < 0) {
    fail_msg("failed to build VLTENC04 header");
  }

  len = (size_t)written;
  out = (uint8_t *)malloc(len + 1u);
  if (out == NULL) {
    fail_msg("out of memory");
  }

  if (snprintf((char *)out,
               len + 1u,
               MAGIC_V4 "\n"
               "version: %u\n"
               "kdf_id: %u\n"
               "kdf: %s\n"
               "cipher_id: %u\n"
               "cipher: %s\n"
               "mac_id: %u\n"
               "mac: %s\n"
               "iterations: %u\n"
               "salt_len: %u\n"
               "iv_len: %u\n"
               "reserved: %u\n"
               "salt_hex: %s\n"
               "iv_hex: %s\n"
               "recovery_source_name: %s\n"
               "recovery_source_encoding: %s\n"
               "recovery_source_bytes: %u\n"
               "recovery_source_base64_len: %u\n"
               "recovery_end_marker: %s\n"
               "recovery_layout: after this blank line, read recovery_source_base64_len bytes, then confirm the next line is recovery_end_marker, then skip one blank line; ciphertext starts after that.\n"
               "recovery_decode_hint: base64 -d vaultcrypt.c.b64 > vaultcrypt.c\n"
               "\n",
               info->hdr.version,
               info->hdr.kdf_id,
               kdf_name(info->hdr.kdf_id),
               info->hdr.cipher_id,
               cipher_name(info->hdr.cipher_id),
               info->hdr.mac_id,
               mac_name(info->hdr.mac_id),
               info->hdr.iterations,
               info->hdr.salt_len,
               info->hdr.iv_len,
               info->hdr.reserved,
               salt_hex,
               iv_hex,
               RECOVERY_SOURCE_NAME,
               RECOVERY_SOURCE_ENCODING,
               info->recovery_source_bytes,
               info->recovery_source_base64_len,
               RECOVERY_END_MARKER) != written) {
    free(out);
    fail_msg("failed to finalize VLTENC04 header");
  }

  *len_out = len;
  return out;
}

static uint8_t *build_v4_prefix(const VaultHeader *hdr,
                                const uint8_t *recovery_source,
                                size_t recovery_source_len,
                                size_t *prefix_len_out,
                                size_t *metadata_len_out) {
  VaultHeaderV4Info info;
  uint8_t *metadata;
  uint8_t *recovery_base64;
  uint8_t *prefix;
  size_t metadata_len;
  size_t recovery_base64_len;
  size_t marker_len = strlen(RECOVERY_MARKER_SUFFIX);

  if (recovery_source_len > UINT32_MAX) {
    fail_msg("recovery source is too large");
  }

  info.hdr = *hdr;
  info.recovery_source_bytes = (uint32_t)recovery_source_len;
  recovery_base64 = base64_encode_wrapped(recovery_source, recovery_source_len, &recovery_base64_len);
  if (recovery_base64_len > UINT32_MAX) {
    free(recovery_base64);
    fail_msg("recovery source base64 payload is too large");
  }
  info.recovery_source_base64_len = (uint32_t)recovery_base64_len;
  metadata = serialize_v4_metadata(&info, &metadata_len);

  prefix = (uint8_t *)malloc(metadata_len + recovery_base64_len + marker_len);
  if (prefix == NULL) {
    free(metadata);
    free(recovery_base64);
    fail_msg("out of memory");
  }

  memcpy(prefix, metadata, metadata_len);
  memcpy(prefix + metadata_len, recovery_base64, recovery_base64_len);
  memcpy(prefix + metadata_len + recovery_base64_len, RECOVERY_MARKER_SUFFIX, marker_len);
  *prefix_len_out = metadata_len + recovery_base64_len + marker_len;
  *metadata_len_out = metadata_len;

  free(metadata);
  free(recovery_base64);
  return prefix;
}

static VaultFormat detect_format(const uint8_t magic[MAGIC_LEN]) {
  if (memcmp(magic, MAGIC_V3, MAGIC_LEN) == 0) {
    return FORMAT_V3;
  }
  if (memcmp(magic, MAGIC_V4, MAGIC_LEN) == 0) {
    return FORMAT_V4;
  }
  return FORMAT_UNKNOWN;
}

static void validate_header_common(const VaultHeader *hdr) {
  if ((hdr->version != VERSION_V3 && hdr->version != VERSION_V4) ||
      hdr->kdf_id != KDF_ID_PBKDF2_SHA256 ||
      hdr->cipher_id != CIPHER_ID_AES256_CTR ||
      hdr->mac_id != MAC_ID_HMAC_SHA256_ETM) {
    fail_msg("unsupported vaultcrypt parameters");
  }
  if (hdr->salt_len != SALT_LEN || hdr->iv_len != IV_LEN) {
    fail_msg("unsupported salt or IV size in vaultcrypt header");
  }
  if (hdr->reserved != HEADER_RESERVED) {
    fail_msg("unsupported vaultcrypt header flags");
  }
  if (hdr->iterations < MIN_ITERATIONS) {
    fail_msg("stored PBKDF2 iteration count is below the supported minimum");
  }
}

static void parse_header_v3(const uint8_t in[V3_HEADER_LEN], VaultHeader *hdr) {
  if (detect_format(in) != FORMAT_V3) {
    fail_msg("file does not start with a VLTENC03 header");
  }

  hdr->version = read_be32(in + 8);
  hdr->kdf_id = read_be32(in + 12);
  hdr->cipher_id = read_be32(in + 16);
  hdr->mac_id = read_be32(in + 20);
  hdr->iterations = read_be32(in + 24);
  hdr->salt_len = read_be32(in + 28);
  hdr->iv_len = read_be32(in + 32);
  hdr->reserved = read_be32(in + 36);
  memcpy(hdr->salt, in + 40, SALT_LEN);
  memcpy(hdr->iv, in + 72, IV_LEN);

  validate_header_common(hdr);
}

static void parse_header_v4(const uint8_t *in, size_t len, VaultHeaderV4Info *info) {
  char *copy;
  char *cursor;
  int saw_blank = 0;
  int saw_version = 0;
  int saw_kdf_id = 0;
  int saw_cipher_id = 0;
  int saw_mac_id = 0;
  int saw_iterations = 0;
  int saw_salt_len = 0;
  int saw_iv_len = 0;
  int saw_reserved = 0;
  int saw_salt_hex = 0;
  int saw_iv_hex = 0;
  int saw_recovery_source_name = 0;
  int saw_recovery_source_encoding = 0;
  int saw_recovery_source_bytes = 0;
  int saw_recovery_source_base64_len = 0;
  int saw_recovery_end_marker = 0;

  if (len < MAGIC_LEN + 2u || detect_format(in) != FORMAT_V4) {
    fail_msg("file does not start with a VLTENC04 header");
  }
  if (in[len - 1u] != '\n' || in[len - 2u] != '\n') {
    fail_msg("unterminated VLTENC04 header");
  }

  memset(info, 0, sizeof(*info));
  copy = (char *)malloc(len + 1u);
  if (copy == NULL) {
    fail_msg("out of memory");
  }
  memcpy(copy, in, len);
  copy[len] = '\0';

  cursor = copy;
  {
    char *nl = strchr(cursor, '\n');
    if (nl == NULL) {
      free(copy);
      fail_msg("invalid VLTENC04 header");
    }
    *nl = '\0';
    if (strcmp(cursor, MAGIC_V4) != 0) {
      free(copy);
      fail_msg("invalid VLTENC04 magic");
    }
    cursor = nl + 1;
  }

  while (*cursor != '\0') {
    char *line = cursor;
    char *nl = strchr(line, '\n');
    if (nl == NULL) {
      free(copy);
      fail_msg("unterminated VLTENC04 header line");
    }
    *nl = '\0';
    cursor = nl + 1;

    char *sep;
    const char *value;

    if (*line == '\0') {
      saw_blank = 1;
      break;
    }

    sep = strstr(line, ": ");
    if (sep == NULL) {
      free(copy);
      fail_msg("malformed VLTENC04 header line");
    }
    *sep = '\0';
    value = sep + 2;

    if (strcmp(line, "version") == 0) {
      info->hdr.version = parse_u32_strict(value, "invalid version in VLTENC04 header");
      saw_version = 1;
    } else if (strcmp(line, "kdf_id") == 0) {
      info->hdr.kdf_id = parse_u32_strict(value, "invalid kdf_id in VLTENC04 header");
      saw_kdf_id = 1;
    } else if (strcmp(line, "cipher_id") == 0) {
      info->hdr.cipher_id = parse_u32_strict(value, "invalid cipher_id in VLTENC04 header");
      saw_cipher_id = 1;
    } else if (strcmp(line, "mac_id") == 0) {
      info->hdr.mac_id = parse_u32_strict(value, "invalid mac_id in VLTENC04 header");
      saw_mac_id = 1;
    } else if (strcmp(line, "iterations") == 0) {
      info->hdr.iterations = parse_u32_strict(value, "invalid iterations in VLTENC04 header");
      saw_iterations = 1;
    } else if (strcmp(line, "salt_len") == 0) {
      info->hdr.salt_len = parse_u32_strict(value, "invalid salt_len in VLTENC04 header");
      saw_salt_len = 1;
    } else if (strcmp(line, "iv_len") == 0) {
      info->hdr.iv_len = parse_u32_strict(value, "invalid iv_len in VLTENC04 header");
      saw_iv_len = 1;
    } else if (strcmp(line, "reserved") == 0) {
      info->hdr.reserved = parse_u32_strict(value, "invalid reserved in VLTENC04 header");
      saw_reserved = 1;
    } else if (strcmp(line, "salt_hex") == 0) {
      hex_decode_exact(value,
                       info->hdr.salt,
                       sizeof(info->hdr.salt),
                       "invalid salt_hex in VLTENC04 header");
      saw_salt_hex = 1;
    } else if (strcmp(line, "iv_hex") == 0) {
      hex_decode_exact(value,
                       info->hdr.iv,
                       sizeof(info->hdr.iv),
                       "invalid iv_hex in VLTENC04 header");
      saw_iv_hex = 1;
    } else if (strcmp(line, "recovery_source_name") == 0) {
      if (strcmp(value, RECOVERY_SOURCE_NAME) != 0) {
        free(copy);
        fail_msg("unsupported recovery_source_name in VLTENC04 header");
      }
      saw_recovery_source_name = 1;
    } else if (strcmp(line, "recovery_source_encoding") == 0) {
      if (strcmp(value, RECOVERY_SOURCE_ENCODING) != 0) {
        free(copy);
        fail_msg("unsupported recovery_source_encoding in VLTENC04 header");
      }
      saw_recovery_source_encoding = 1;
    } else if (strcmp(line, "recovery_source_bytes") == 0) {
      info->recovery_source_bytes =
          parse_u32_strict(value, "invalid recovery_source_bytes in VLTENC04 header");
      saw_recovery_source_bytes = 1;
    } else if (strcmp(line, "recovery_source_base64_len") == 0) {
      info->recovery_source_base64_len =
          parse_u32_strict(value, "invalid recovery_source_base64_len in VLTENC04 header");
      saw_recovery_source_base64_len = 1;
    } else if (strcmp(line, "recovery_end_marker") == 0) {
      if (strcmp(value, RECOVERY_END_MARKER) != 0) {
        free(copy);
        fail_msg("unsupported recovery_end_marker in VLTENC04 header");
      }
      saw_recovery_end_marker = 1;
    }
  }

  free(copy);

  if (!saw_blank ||
      !saw_version ||
      !saw_kdf_id ||
      !saw_cipher_id ||
      !saw_mac_id ||
      !saw_iterations ||
      !saw_salt_len ||
      !saw_iv_len ||
      !saw_reserved ||
      !saw_salt_hex ||
      !saw_iv_hex) {
    fail_msg("incomplete VLTENC04 header");
  }

  if ((saw_recovery_source_name ||
       saw_recovery_source_encoding ||
       saw_recovery_source_bytes ||
       saw_recovery_source_base64_len ||
       saw_recovery_end_marker) &&
      !(saw_recovery_source_name &&
        saw_recovery_source_encoding &&
        saw_recovery_source_bytes &&
        saw_recovery_source_base64_len &&
        saw_recovery_end_marker)) {
    fail_msg("incomplete recovery metadata in VLTENC04 header");
  }

  validate_header_common(&info->hdr);
}

static uint8_t *read_header_v4(FILE *fp, const uint8_t magic[MAGIC_LEN], size_t *header_len_out) {
  uint8_t *buf;
  size_t len = MAGIC_LEN;
  int prev = 0;
  int ch;

  buf = (uint8_t *)malloc(MAX_HEADER_LEN);
  if (buf == NULL) {
    fail_msg("out of memory");
  }
  memcpy(buf, magic, MAGIC_LEN);

  while (len < MAX_HEADER_LEN) {
    ch = fgetc(fp);
    if (ch == EOF) {
      free(buf);
      if (ferror(fp)) {
        fail_errno("read header");
      }
      fail_msg("unexpected end of file in VLTENC04 header");
    }

    buf[len++] = (uint8_t)ch;
    if (prev == '\n' && ch == '\n') {
      *header_len_out = len;
      return buf;
    }
    prev = ch;
  }

  free(buf);
  fail_msg("VLTENC04 header is too large");
  return NULL;
}

static uint8_t *load_v4_prefix(FILE *fp,
                               const uint8_t magic[MAGIC_LEN],
                               VaultHeaderV4Info *info,
                               size_t *prefix_len_out,
                               size_t *metadata_len_out) {
  uint8_t *metadata = read_header_v4(fp, magic, metadata_len_out);
  uint8_t *prefix;
  size_t marker_len = strlen(RECOVERY_MARKER_SUFFIX);

  parse_header_v4(metadata, *metadata_len_out, info);

  if (info->recovery_source_base64_len == 0u) {
    *prefix_len_out = *metadata_len_out;
    return metadata;
  }

  prefix = (uint8_t *)malloc(*metadata_len_out + info->recovery_source_base64_len + marker_len);
  if (prefix == NULL) {
    free(metadata);
    fail_msg("out of memory");
  }

  memcpy(prefix, metadata, *metadata_len_out);
  read_exact(fp,
             prefix + *metadata_len_out,
             info->recovery_source_base64_len,
             "read recovery source");
  read_exact(fp,
             prefix + *metadata_len_out + info->recovery_source_base64_len,
             marker_len,
             "read recovery marker");
  if (memcmp(prefix + *metadata_len_out + info->recovery_source_base64_len,
             RECOVERY_MARKER_SUFFIX,
             marker_len) != 0) {
    free(metadata);
    free(prefix);
    fail_msg("invalid recovery marker block in VLTENC04 file");
  }

  *prefix_len_out = *metadata_len_out + info->recovery_source_base64_len + marker_len;
  free(metadata);
  return prefix;
}

static char *prompt_passphrase(const char *prompt, int confirm, int require_tty) {
  char first[PASS_MAX];
  char second[PASS_MAX];
  char *result;
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
  lock_memory_best_effort(result, strlen(result) + 1u);
  secure_release_buffer(first, sizeof(first));
  secure_release_buffer(second, sizeof(second));
  return result;
}

static char *keychain_default_account(void) {
  const char *user = getenv("USER");

  if (user == NULL || user[0] == '\0') {
    fail_msg("keychain lookup requires --passphrase-keychain-account or $USER");
  }
  return xstrdup(user);
}

static char *shell_single_quote(const char *src) {
  size_t len = 2u;
  const char *p;
  char *out;
  char *dst;

  for (p = src; *p != '\0'; ++p) {
    len += *p == '\'' ? 4u : 1u;
  }

  out = (char *)malloc(len + 1u);
  if (out == NULL) {
    fail_msg("out of memory");
  }

  dst = out;
  *dst++ = '\'';
  for (p = src; *p != '\0'; ++p) {
    if (*p == '\'') {
      memcpy(dst, "'\\''", 4u);
      dst += 4u;
    } else {
      *dst++ = *p;
    }
  }
  *dst++ = '\'';
  *dst = '\0';
  return out;
}

static char *load_passphrase_from_keychain(const Options *opts) {
  const char *service;
  char *owned_account = NULL;
  const char *account;
  char *service_quoted = NULL;
  char *account_quoted = NULL;
  char *command = NULL;
  FILE *fp;
  size_t cap = 0u;
  ssize_t line_len;
  char *line = NULL;
  char *result;

  service = opts->keychain_service;
  if (service == NULL || service[0] == '\0') {
    fail_msg("keychain service name is required");
  }

  if (opts->keychain_account != NULL && opts->keychain_account[0] != '\0') {
    account = opts->keychain_account;
  } else {
    owned_account = keychain_default_account();
    account = owned_account;
  }

  service_quoted = shell_single_quote(service);
  account_quoted = shell_single_quote(account);
  command = (char *)malloc(strlen(service_quoted) + strlen(account_quoted) + 128u);
  if (command == NULL) {
    free(service_quoted);
    free(account_quoted);
    free(owned_account);
    fail_msg("out of memory");
  }
  snprintf(command,
           strlen(service_quoted) + strlen(account_quoted) + 128u,
           "/usr/bin/security find-generic-password -a %s -s %s -w 2>/dev/null",
           account_quoted,
           service_quoted);
  fp = popen(command, "r");
  if (fp == NULL) {
    free(command);
    free(service_quoted);
    free(account_quoted);
    free(owned_account);
    fail_errno("popen security");
  }

  line_len = getline(&line, &cap, fp);
  if (pclose(fp) != 0 || line_len < 0) {
    free(line);
    free(command);
    free(service_quoted);
    free(account_quoted);
    free(owned_account);
    fail_msg("keychain lookup failed");
  }
  if (line_len > 0 && line[line_len - 1] == '\n') {
    line[--line_len] = '\0';
  }
  if (line_len == 0) {
    free(line);
    free(command);
    free(service_quoted);
    free(account_quoted);
    free(owned_account);
    fail_msg("keychain item contained an empty passphrase");
  }

  result = xstrdup(line);
  lock_memory_best_effort(result, strlen(result) + 1u);
  free(line);
  free(command);
  free(service_quoted);
  free(account_quoted);
  free(owned_account);
  return result;
}

static char *obtain_passphrase(const char *prompt, int confirm, const Options *opts) {
  if (opts->keychain_service != NULL) {
    (void)prompt;
    (void)confirm;
    return load_passphrase_from_keychain(opts);
  }
  return prompt_passphrase(prompt, confirm, opts->require_tty);
}

static CCCryptorRef create_ctr_cryptor(CCOperation op,
                                       const uint8_t key[ENC_KEY_LEN],
                                       const uint8_t iv[IV_LEN]) {
  CCCryptorRef cryptor = NULL;
  CCCryptorStatus status;

  status = CCCryptorCreateWithMode(op,
                                   kCCModeCTR,
                                   kCCAlgorithmAES,
                                   ccNoPadding,
                                   iv,
                                   key,
                                   ENC_KEY_LEN,
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

static void copy_file_to_stream(FILE *src, FILE *dst) {
  uint8_t buf[IO_CHUNK_SIZE];
  size_t nread;

  rewind(src);
  while ((nread = fread(buf, 1, sizeof(buf), src)) > 0u) {
    write_exact(dst, buf, nread, "write output");
  }
  if (ferror(src)) {
    fail_errno("read decrypted temporary file");
  }
  if (fflush(dst) != 0) {
    fail_errno("flush output");
  }
}

static void seek_to_offset(FILE *fp, off_t offset, const char *label) {
  if (fseeko(fp, offset, SEEK_SET) != 0) {
    fail_errno(label);
  }
}

static void authenticate_ciphertext(FILE *in,
                                    uint64_t ciphertext_len,
                                    const uint8_t *header_bytes,
                                    size_t header_len,
                                    const uint8_t mac_key[MAC_KEY_LEN]) {
  uint8_t inbuf[IO_CHUNK_SIZE];
  uint8_t expected_tag[TAG_LEN];
  uint8_t actual_tag[TAG_LEN];
  uint64_t remaining = ciphertext_len;
  CCHmacContext hmac;

  memset(actual_tag, 0, sizeof(actual_tag));
  CCHmacInit(&hmac, kCCHmacAlgSHA256, mac_key, MAC_KEY_LEN);
  CCHmacUpdate(&hmac, header_bytes, header_len);

  while (remaining > 0u) {
    size_t want = remaining > sizeof(inbuf) ? sizeof(inbuf) : (size_t)remaining;

    read_exact(in, inbuf, want, "read ciphertext");
    CCHmacUpdate(&hmac, inbuf, want);
    remaining -= want;
  }

  read_exact(in, expected_tag, sizeof(expected_tag), "read authentication tag");
  if (fgetc(in) != EOF) {
    fail_msg("trailing data after authentication tag");
  }
  if (ferror(in)) {
    fail_errno("read trailer");
  }

  CCHmacFinal(&hmac, actual_tag);
  if (!constant_time_eq(expected_tag, actual_tag, sizeof(expected_tag))) {
    fail_msg("authentication failed: wrong passphrase or corrupted file");
  }
}

static void decrypt_ciphertext(FILE *in,
                               FILE *out,
                               uint64_t ciphertext_len,
                               const uint8_t enc_key[ENC_KEY_LEN],
                               const uint8_t iv[IV_LEN]) {
  uint8_t inbuf[IO_CHUNK_SIZE];
  uint8_t outbuf[IO_CHUNK_SIZE + 32u];
  uint64_t remaining = ciphertext_len;
  CCCryptorRef cryptor;

  cryptor = create_ctr_cryptor(kCCDecrypt, enc_key, iv);
  while (remaining > 0u) {
    size_t want = remaining > sizeof(inbuf) ? sizeof(inbuf) : (size_t)remaining;
    size_t produced = 0;
    CCCryptorStatus status;

    read_exact(in, inbuf, want, "read ciphertext");
    status = CCCryptorUpdate(cryptor,
                             inbuf,
                             want,
                             outbuf,
                             sizeof(outbuf),
                             &produced);
    if (status != kCCSuccess || produced != want) {
      CCCryptorRelease(cryptor);
      fail_msg("decryption failed");
    }

    write_exact(out, outbuf, produced, "write decrypted data");
    remaining -= want;
  }

  {
    size_t produced = 0;
    CCCryptorStatus status = CCCryptorFinal(cryptor,
                                            outbuf,
                                            sizeof(outbuf),
                                            &produced);
    CCCryptorRelease(cryptor);
    if (status != kCCSuccess || produced != 0u) {
      fail_msg("final decryption step failed");
    }
  }
}

static void encrypt_file_with_passphrase(const char *input_path,
                                         const char *output_path,
                                         uint32_t iterations,
                                         const Options *opts,
                                         const char *passphrase,
                                         int require_confirm) {
  FILE *in = NULL;
  FILE *out = NULL;
  char *temp_path = NULL;
  char *owned_output = NULL;
  char *owned_passphrase = NULL;
  uint8_t *prefix_bytes = NULL;
  uint8_t *recovery_source = NULL;
  size_t prefix_len = 0;
  size_t recovery_source_len = 0;
  size_t metadata_len = 0;
  uint8_t enc_key[ENC_KEY_LEN];
  uint8_t mac_key[MAC_KEY_LEN];
  uint8_t inbuf[IO_CHUNK_SIZE];
  uint8_t outbuf[IO_CHUNK_SIZE + 32u];
  uint8_t tag[TAG_LEN];
  VaultHeader hdr;
  CCHmacContext hmac;
  CCCryptorRef cryptor;

  memset(enc_key, 0, sizeof(enc_key));
  memset(mac_key, 0, sizeof(mac_key));
  memset(tag, 0, sizeof(tag));

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

  if (passphrase == NULL) {
    owned_passphrase = obtain_passphrase("Passphrase: ", require_confirm, opts);
    passphrase = owned_passphrase;
  }
  fill_header(&hdr, iterations, VERSION_V4);
  recovery_source = load_recovery_source(&recovery_source_len);
  prefix_bytes = build_v4_prefix(&hdr,
                                 recovery_source,
                                 recovery_source_len,
                                 &prefix_len,
                                 &metadata_len);
  derive_keys(passphrase, hdr.salt, hdr.iterations, enc_key, mac_key);
  lock_memory_best_effort(enc_key, sizeof(enc_key));
  lock_memory_best_effort(mac_key, sizeof(mac_key));

  if (strcmp(input_path, "-") == 0) {
    in = stdin;
  } else {
    in = open_input_file(input_path);
  }
  out = open_output_temp(output_path, &temp_path, opts->force);

  write_exact(out, prefix_bytes, prefix_len, "write header");
  CCHmacInit(&hmac, kCCHmacAlgSHA256, mac_key, sizeof(mac_key));
  CCHmacUpdate(&hmac, prefix_bytes, prefix_len);

  cryptor = create_ctr_cryptor(kCCEncrypt, enc_key, hdr.iv);
  for (;;) {
    size_t nread = fread(inbuf, 1, sizeof(inbuf), in);
    size_t produced = 0;
    CCCryptorStatus status;

    if (nread == 0u) {
      if (ferror(in)) {
        CCCryptorRelease(cryptor);
        fail_errno("read input");
      }
      break;
    }

    status = CCCryptorUpdate(cryptor,
                             inbuf,
                             nread,
                             outbuf,
                             sizeof(outbuf),
                             &produced);
    if (status != kCCSuccess || produced != nread) {
      CCCryptorRelease(cryptor);
      fail_msg("encryption failed");
    }

    CCHmacUpdate(&hmac, outbuf, produced);
    write_exact(out, outbuf, produced, "write ciphertext");
  }
  {
    size_t produced = 0;
    CCCryptorStatus status = CCCryptorFinal(cryptor,
                                            outbuf,
                                            sizeof(outbuf),
                                            &produced);
    CCCryptorRelease(cryptor);
    if (status != kCCSuccess || produced != 0u) {
      fail_msg("final encryption step failed");
    }
  }

  CCHmacFinal(&hmac, tag);
  write_exact(out, tag, sizeof(tag), "write tag");
  finalize_output_file(out, temp_path, output_path);

  if (in != NULL && in != stdin) {
    fclose(in);
  }
  free(prefix_bytes);
  free(recovery_source);
  secure_release_buffer(enc_key, sizeof(enc_key));
  secure_release_buffer(mac_key, sizeof(mac_key));
  secure_free_string(&owned_passphrase);
  free(owned_output);
}

static void encrypt_command(const char *input_path,
                            const char *output_path,
                            uint32_t iterations,
                            const Options *opts) {
  encrypt_file_with_passphrase(input_path, output_path, iterations, opts, NULL, 1);
}

static void decrypt_file_with_passphrase(const char *input_path,
                                         const char *output_path,
                                         const Options *opts,
                                         const char *passphrase) {
  FILE *in;
  FILE *out;
  char *temp_path = NULL;
  uint8_t magic[MAGIC_LEN];
  uint8_t header_v3[V3_HEADER_LEN];
  uint8_t *prefix_bytes = NULL;
  size_t prefix_len = 0;
  size_t metadata_len = 0;
  uint8_t enc_key[ENC_KEY_LEN];
  uint8_t mac_key[MAC_KEY_LEN];
  char *owned_passphrase = NULL;
  VaultFormat format;
  VaultHeader hdr;
  VaultHeaderV4Info v4info;
  uint64_t total_size;
  uint64_t ciphertext_len;

  memset(enc_key, 0, sizeof(enc_key));
  memset(mac_key, 0, sizeof(mac_key));

  if (input_path == NULL) {
    usage(stderr, 2);
  }
  if (strcmp(input_path, "-") == 0) {
    fail_msg("decrypt requires a regular input file");
  }
  if (output_path == NULL || (strcmp(output_path, "-") == 0 && !opts->allow_stdout)) {
    fail_msg("decrypt requires -o PATH or explicit stdout via -o - or --stdout");
  }
  if (output_path != NULL &&
      strcmp(output_path, "-") != 0 &&
      strcmp(input_path, output_path) == 0) {
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
    fclose(in);
    fail_msg("unsupported vaultcrypt file format");
  }

  if (format == FORMAT_V3) {
    memcpy(header_v3, magic, MAGIC_LEN);
    read_exact(in, header_v3 + MAGIC_LEN, V3_HEADER_LEN - MAGIC_LEN, "read header");
    parse_header_v3(header_v3, &hdr);
    prefix_bytes = header_v3;
    prefix_len = V3_HEADER_LEN;
  } else {
    prefix_bytes = load_v4_prefix(in, magic, &v4info, &prefix_len, &metadata_len);
    hdr = v4info.hdr;
  }
  if (total_size < prefix_len + TAG_LEN) {
    if (format == FORMAT_V4) {
      free(prefix_bytes);
    }
    fclose(in);
    fail_msg("file is too small to be a vaultcrypt ciphertext");
  }
  ciphertext_len = total_size - prefix_len - TAG_LEN;

  if (passphrase == NULL) {
    owned_passphrase = obtain_passphrase("Passphrase: ", 0, opts);
    passphrase = owned_passphrase;
  }
  derive_keys(passphrase, hdr.salt, hdr.iterations, enc_key, mac_key);
  lock_memory_best_effort(enc_key, sizeof(enc_key));
  lock_memory_best_effort(mac_key, sizeof(mac_key));

  authenticate_ciphertext(in, ciphertext_len, prefix_bytes, prefix_len, mac_key);
  seek_to_offset(in, (off_t)prefix_len, "seek ciphertext");

  if (strcmp(output_path, "-") == 0) {
    out = tmpfile();
    if (out == NULL) {
      fclose(in);
      fail_errno("tmpfile");
    }
  } else {
    out = open_output_temp(output_path, &temp_path, opts->force);
  }

  if (ferror(in)) {
    if (temp_path != NULL) {
      fclose(out);
      unlink(temp_path);
    } else {
      fclose(out);
    }
    fclose(in);
    fail_errno("read ciphertext");
  }

  decrypt_ciphertext(in, out, ciphertext_len, enc_key, hdr.iv);
  fclose(in);
  if (temp_path != NULL) {
    finalize_output_file(out, temp_path, output_path);
  } else {
    copy_file_to_stream(out, stdout);
    fclose(out);
  }

  if (format == FORMAT_V4) {
    free(prefix_bytes);
  }
  secure_release_buffer(enc_key, sizeof(enc_key));
  secure_release_buffer(mac_key, sizeof(mac_key));
  secure_free_string(&owned_passphrase);
}

static void decrypt_command(const char *input_path, const char *output_path, const Options *opts) {
  decrypt_file_with_passphrase(input_path, output_path, opts, NULL);
}

static char *make_manifest_temp_path(const char *vault_dir) {
  return join_path(vault_dir, ".vaultcrypt-manifest.plain.tmp");
}

static void load_manifest_if_present(const char *vault_dir,
                                     const Options *opts,
                                     const char *passphrase,
                                     Manifest *manifest) {
  char *cipher_path = manifest_path(vault_dir);

  if (path_exists(cipher_path)) {
    char *plain_path = make_manifest_temp_path(vault_dir);

    decrypt_file_with_passphrase(cipher_path, plain_path, opts, passphrase);
    parse_manifest_plaintext(plain_path, manifest);
    if (unlink(plain_path) != 0) {
      free(plain_path);
      free(cipher_path);
      fail_errno("unlink manifest temp");
    }
    free(plain_path);
  }
  free(cipher_path);
}

static void store_manifest(const char *vault_dir,
                           const Options *opts,
                           const char *passphrase,
                           uint32_t iterations,
                           const Manifest *manifest) {
  char *plain_path = make_manifest_temp_path(vault_dir);
  char *cipher_path = manifest_path(vault_dir);
  Options local_opts = *opts;

  write_manifest_plaintext(plain_path, manifest);
  local_opts.force = 1;
  encrypt_file_with_passphrase(plain_path, cipher_path, iterations, &local_opts, passphrase, 0);
  if (unlink(plain_path) != 0) {
    free(plain_path);
    free(cipher_path);
    fail_errno("unlink manifest temp");
  }
  free(plain_path);
  free(cipher_path);
}

static void remove_manifest_index(Manifest *manifest, size_t index) {
  size_t i;

  free(manifest->items[index].rel_path);
  for (i = index + 1u; i < manifest->len; ++i) {
    manifest->items[i - 1u] = manifest->items[i];
  }
  manifest->len--;
}

static void syncdir_walk(const char *source_dir,
                         const char *vault_dir,
                         const char *rel_path,
                         const uint8_t name_key[NAME_KEY_LEN],
                         const Options *opts,
                         const char *passphrase,
                         uint32_t iterations,
                         Manifest *manifest,
                         size_t *encrypted_count,
                         size_t *skipped_count) {
  char *dir_path = rel_path[0] == '\0' ? xstrdup(source_dir) : join_path(source_dir, rel_path);
  DIR *dir = opendir(dir_path);
  struct dirent *entry;

  if (dir == NULL) {
    free(dir_path);
    fail_errno("opendir");
  }

  while ((entry = readdir(dir)) != NULL) {
    char *child_rel;
    char *source_path;
    struct stat st;

    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    if (rel_path[0] == '\0') {
      child_rel = xstrdup(entry->d_name);
    } else {
      char *prefix = join_path(rel_path, entry->d_name);
      child_rel = prefix;
    }
    source_path = join_path(source_dir, child_rel);
    if (lstat(source_path, &st) != 0) {
      const int saved_errno = errno;
      free(child_rel);
      closedir(dir);
      free(dir_path);
      fprintf(stderr, "vaultcrypt: lstat failed: %s: %s\n", source_path, strerror(saved_errno));
      free(source_path);
      exit(1);
    }

    if (S_ISDIR(st.st_mode)) {
      syncdir_walk(source_dir,
                   vault_dir,
                   child_rel,
                   name_key,
                   opts,
                   passphrase,
                   iterations,
                   manifest,
                   encrypted_count,
                   skipped_count);
      free(child_rel);
      free(source_path);
      continue;
    }

    if (S_ISREG(st.st_mode)) {
      ManifestEntry *manifest_entry;
      char sha256_hex[SHA256_HEX_LEN + 1u];
      uint64_t size = 0;
      char *cipher_path = vault_file_path(vault_dir, child_rel, name_key);
      int needs_encrypt = 1;

      sha256_file_hex(source_path, sha256_hex, &size);
      manifest_entry = manifest_upsert(manifest, child_rel);
      manifest_entry->seen = 1;

      if (path_exists(cipher_path) &&
          manifest_entry->size == size &&
          strcmp(manifest_entry->sha256_hex, sha256_hex) == 0) {
        needs_encrypt = 0;
      }

      if (needs_encrypt) {
        Options local_opts = *opts;
        local_opts.force = 1;
        ensure_parent_dir(cipher_path);
        encrypt_file_with_passphrase(source_path,
                                     cipher_path,
                                     iterations,
                                     &local_opts,
                                     passphrase,
                                     0);
        (*encrypted_count)++;
      } else {
        (*skipped_count)++;
      }

      manifest_entry->size = size;
      memcpy(manifest_entry->sha256_hex, sha256_hex, sizeof(sha256_hex));
      remove_legacy_cipher_if_present(vault_dir, child_rel, cipher_path);

      free(cipher_path);
      free(child_rel);
      free(source_path);
      continue;
    }

    free(child_rel);
    free(source_path);
  }

  if (closedir(dir) != 0) {
    free(dir_path);
    fail_errno("closedir");
  }
  free(dir_path);
}

static void prune_removed_entries(const char *vault_dir,
                                  const uint8_t name_key[NAME_KEY_LEN],
                                  Manifest *manifest,
                                  size_t *removed_count) {
  size_t i = 0u;

  while (i < manifest->len) {
    ManifestEntry *entry = &manifest->items[i];

    if (entry->seen) {
      ++i;
      continue;
    }

    {
      char *cipher_path = vault_file_path(vault_dir, entry->rel_path, name_key);
      if (path_exists(cipher_path) && unlink(cipher_path) != 0) {
        free(cipher_path);
        fail_errno("unlink stale ciphertext");
      }
      remove_legacy_cipher_if_present(vault_dir, entry->rel_path, cipher_path);
      free(cipher_path);
    }
    remove_manifest_index(manifest, i);
    (*removed_count)++;
  }
}

static void syncdir_command(const char *source_dir,
                            const char *vault_dir,
                            uint32_t iterations,
                            const Options *opts) {
  Manifest manifest;
  char *passphrase;
  uint8_t name_key[NAME_KEY_LEN];
  size_t encrypted_count = 0u;
  size_t skipped_count = 0u;
  size_t removed_count = 0u;

  if (source_dir == NULL || vault_dir == NULL) {
    usage(stderr, 2);
  }
  require_directory(source_dir, "syncdir input must be a directory");
  ensure_dir_recursive(vault_dir);
  require_directory(vault_dir, "syncdir output must be a directory");
  if (iterations < MIN_ITERATIONS) {
    fail_msg("iteration count is too low");
  }

  manifest_init(&manifest);
  passphrase = obtain_passphrase("Passphrase: ", 1, opts);
  derive_name_key(passphrase, name_key);
  load_manifest_if_present(vault_dir, opts, passphrase, &manifest);
  manifest_reset_seen(&manifest);
  syncdir_walk(source_dir,
               vault_dir,
               "",
               name_key,
               opts,
               passphrase,
               iterations,
               &manifest,
               &encrypted_count,
               &skipped_count);
  prune_removed_entries(vault_dir, name_key, &manifest, &removed_count);
  store_manifest(vault_dir, opts, passphrase, iterations, &manifest);
  printf("syncdir: encrypted=%zu skipped=%zu removed=%zu\n",
         encrypted_count,
         skipped_count,
         removed_count);
  manifest_free(&manifest);
  secure_release_buffer(name_key, sizeof(name_key));
  secure_free_string(&passphrase);
}

static void restoredir_command(const char *vault_dir, const char *output_dir, const Options *opts) {
  Manifest manifest;
  char *passphrase;
  uint8_t name_key[NAME_KEY_LEN];
  size_t restored_count = 0u;
  size_t skipped_count = 0u;
  size_t i;

  if (vault_dir == NULL || output_dir == NULL) {
    usage(stderr, 2);
  }
  require_directory(vault_dir, "restoredir input must be a directory");
  ensure_dir_recursive(output_dir);
  require_directory(output_dir, "restoredir output must be a directory");

  manifest_init(&manifest);
  passphrase = obtain_passphrase("Passphrase: ", 0, opts);
  derive_name_key(passphrase, name_key);
  load_manifest_if_present(vault_dir, opts, passphrase, &manifest);
  if (manifest.len == 0u) {
    manifest_free(&manifest);
    secure_release_buffer(name_key, sizeof(name_key));
    secure_free_string(&passphrase);
    fail_msg("manifest is missing or empty");
  }

  for (i = 0; i < manifest.len; ++i) {
    ManifestEntry *entry = &manifest.items[i];
    char existing_sha256[SHA256_HEX_LEN + 1u];
    uint64_t existing_size = 0u;
    char *cipher_path = restore_cipher_path(vault_dir, entry->rel_path, name_key);
    char *output_path = join_path(output_dir, entry->rel_path);
    int needs_restore = 1;
    Options local_opts = *opts;

    if (!path_exists(cipher_path)) {
      free(cipher_path);
      free(output_path);
      manifest_free(&manifest);
      secure_release_buffer(name_key, sizeof(name_key));
      secure_free_string(&passphrase);
      fail_msg("ciphertext file listed in manifest is missing");
    }

    if (path_exists(output_path)) {
      sha256_file_hex(output_path, existing_sha256, &existing_size);
      if (existing_size == entry->size &&
          strcmp(existing_sha256, entry->sha256_hex) == 0) {
        needs_restore = 0;
      }
    }

    if (needs_restore) {
      local_opts.force = 1;
      ensure_parent_dir(output_path);
      decrypt_file_with_passphrase(cipher_path, output_path, &local_opts, passphrase);
      restored_count++;
    } else {
      skipped_count++;
    }

    free(cipher_path);
    free(output_path);
  }

  printf("restoredir: restored=%zu skipped=%zu\n", restored_count, skipped_count);
  manifest_free(&manifest);
  secure_release_buffer(name_key, sizeof(name_key));
  secure_free_string(&passphrase);
}

static void info_command(const char *input_path, const Options *opts) {
  FILE *in;
  uint8_t magic[MAGIC_LEN];
  uint8_t header_v3[V3_HEADER_LEN];
  uint8_t *prefix_bytes = NULL;
  size_t prefix_len = 0;
  size_t metadata_len = 0;
  VaultFormat format;
  char *metadata_hex = NULL;
  char *prefix_hex = NULL;
  char salt_hex[(SALT_LEN * 2u) + 1u];
  char iv_hex[(IV_LEN * 2u) + 1u];
  VaultHeader hdr;
  VaultHeaderV4Info v4info;

  if (input_path == NULL || strcmp(input_path, "-") == 0) {
    fail_msg("info requires a regular input file");
  }

  in = open_input_file(input_path);
  read_exact(in, magic, sizeof(magic), "read magic");
  format = detect_format(magic);
  if (format == FORMAT_V3) {
    rewind(in);
    read_exact(in, header_v3, sizeof(header_v3), "read header");
    prefix_bytes = header_v3;
    prefix_len = V3_HEADER_LEN;
    parse_header_v3(prefix_bytes, &hdr);
  } else if (format == FORMAT_V4) {
    rewind(in);
    read_exact(in, magic, sizeof(magic), "read magic");
    prefix_bytes = load_v4_prefix(in, magic, &v4info, &prefix_len, &metadata_len);
    hdr = v4info.hdr;
  } else {
    fclose(in);
    fail_msg("unsupported vaultcrypt file format");
  }
  fclose(in);
  if (metadata_len == 0u) {
    metadata_len = prefix_len;
  }
  metadata_hex = (char *)malloc((metadata_len * 2u) + 1u);
  prefix_hex = (char *)malloc((prefix_len * 2u) + 1u);
  if (metadata_hex == NULL || prefix_hex == NULL) {
    if (format == FORMAT_V4) {
      free(prefix_bytes);
    }
    free(metadata_hex);
    free(prefix_hex);
    fail_msg("out of memory");
  }
  hex_encode(prefix_bytes, metadata_len, metadata_hex, (metadata_len * 2u) + 1u);
  hex_encode(prefix_bytes, prefix_len, prefix_hex, (prefix_len * 2u) + 1u);
  hex_encode(hdr.salt, sizeof(hdr.salt), salt_hex, sizeof(salt_hex));
  hex_encode(hdr.iv, sizeof(hdr.iv), iv_hex, sizeof(iv_hex));

  if (opts->info_json) {
    printf("{\n"
           "  \"file\": \"%s\",\n"
           "  \"format\": \"%s\",\n"
           "  \"header_len\": %zu,\n"
           "  \"authenticated_prefix_len\": %zu,\n"
           "  \"version\": %u,\n"
           "  \"kdf_id\": %u,\n"
           "  \"kdf\": \"%s\",\n"
           "  \"cipher_id\": %u,\n"
           "  \"cipher\": \"%s\",\n"
           "  \"mac_id\": %u,\n"
           "  \"mac\": \"%s\",\n"
           "  \"iterations\": %u,\n"
           "  \"salt_len\": %u,\n"
           "  \"iv_len\": %u,\n"
           "  \"reserved\": %u,\n"
           "  \"salt_hex\": \"%s\",\n"
           "  \"iv_hex\": \"%s\",\n"
           "  \"header_hex\": \"%s\",\n"
           "  \"recovery_source_bytes\": %u,\n"
           "  \"recovery_source_base64_len\": %u,\n"
           "  \"authenticated_prefix_hex\": \"%s\"\n"
           "}\n",
           input_path,
           format == FORMAT_V4 ? MAGIC_V4 : MAGIC_V3,
           metadata_len,
           prefix_len,
           hdr.version,
           hdr.kdf_id,
           kdf_name(hdr.kdf_id),
           hdr.cipher_id,
           cipher_name(hdr.cipher_id),
           hdr.mac_id,
           mac_name(hdr.mac_id),
           hdr.iterations,
           hdr.salt_len,
           hdr.iv_len,
           hdr.reserved,
           salt_hex,
           iv_hex,
           metadata_hex,
           format == FORMAT_V4 ? v4info.recovery_source_bytes : 0u,
           format == FORMAT_V4 ? v4info.recovery_source_base64_len : 0u,
           prefix_hex);
    if (format == FORMAT_V4) {
      free(prefix_bytes);
    }
    free(metadata_hex);
    free(prefix_hex);
    return;
  }

  printf("file: %s\n", input_path);
  printf("format: %s\n", format == FORMAT_V4 ? MAGIC_V4 : MAGIC_V3);
  printf("header_len: %zu\n", metadata_len);
  printf("authenticated_prefix_len: %zu\n", prefix_len);
  printf("magic_ascii: %.8s\n", prefix_bytes);
  printf("version: %u\n", hdr.version);
  printf("kdf_id: %u\n", hdr.kdf_id);
  printf("kdf: %s\n", kdf_name(hdr.kdf_id));
  printf("cipher_id: %u\n", hdr.cipher_id);
  printf("cipher: %s\n", cipher_name(hdr.cipher_id));
  printf("mac_id: %u\n", hdr.mac_id);
  printf("mac: %s\n", mac_name(hdr.mac_id));
  printf("iterations: %u\n", hdr.iterations);
  printf("salt_len: %u\n", hdr.salt_len);
  printf("iv_len: %u\n", hdr.iv_len);
  printf("reserved: %u\n", hdr.reserved);
  printf("salt_hex: %s\n", salt_hex);
  printf("iv_hex: %s\n", iv_hex);
  if (format == FORMAT_V4) {
    printf("recovery_source_bytes: %u\n", v4info.recovery_source_bytes);
    printf("recovery_source_base64_len: %u\n", v4info.recovery_source_base64_len);
    printf("recovery_extract_note: after the blank line, copy the next %u bytes into %s.b64; the next line must be %s; skip one blank line; ciphertext starts after that.\n",
           v4info.recovery_source_base64_len,
           RECOVERY_SOURCE_NAME,
           RECOVERY_END_MARKER);
  }
  printf("header_hex: %s\n", metadata_hex);
  printf("header_dump:\n");
  print_header_dump(prefix_bytes, metadata_len);
  if (format == FORMAT_V4) {
    free(prefix_bytes);
  }
  free(metadata_hex);
  free(prefix_hex);
}

static void selftest_v3(void) {
  static const char plaintext[] = "vaultcrypt minimal v3 self-test payload\n";
  static const char passphrase[] = "correct horse battery staple selftest";
  static const uint8_t recovery_source[] =
      "/* selftest recovery source */\nint main(void) { return 0; }\n";
  VaultHeader hdr;
  VaultHeader legacy_hdr;
  uint8_t legacy_header[V3_HEADER_LEN];
  uint8_t *prefix_bytes = NULL;
  size_t prefix_len = 0;
  size_t metadata_len = 0;
  uint8_t enc_key[ENC_KEY_LEN];
  uint8_t mac_key[MAC_KEY_LEN];
  uint8_t wrong_enc_key[ENC_KEY_LEN];
  uint8_t wrong_mac_key[MAC_KEY_LEN];
  uint8_t ciphertext[sizeof(plaintext) + 32u];
  uint8_t decrypted[sizeof(plaintext) + 32u];
  uint8_t tag[TAG_LEN];
  uint8_t actual_tag[TAG_LEN];
  size_t produced = 0;
  CCHmacContext hmac;
  CCCryptorRef cryptor;

  memset(enc_key, 0, sizeof(enc_key));
  memset(mac_key, 0, sizeof(mac_key));
  memset(wrong_enc_key, 0, sizeof(wrong_enc_key));
  memset(wrong_mac_key, 0, sizeof(wrong_mac_key));
  memset(ciphertext, 0, sizeof(ciphertext));
  memset(decrypted, 0, sizeof(decrypted));

  fill_header(&hdr, DEFAULT_ITERATIONS, VERSION_V4);
  prefix_bytes = build_v4_prefix(&hdr,
                                 recovery_source,
                                 sizeof(recovery_source) - 1u,
                                 &prefix_len,
                                 &metadata_len);
  derive_keys(passphrase, hdr.salt, hdr.iterations, enc_key, mac_key);

  cryptor = create_ctr_cryptor(kCCEncrypt, enc_key, hdr.iv);
  if (CCCryptorUpdate(cryptor,
                      plaintext,
                      sizeof(plaintext),
                      ciphertext,
                      sizeof(ciphertext),
                      &produced) != kCCSuccess ||
      produced != sizeof(plaintext)) {
    CCCryptorRelease(cryptor);
    fail_msg("selftest encryption failed");
  }
  CCCryptorRelease(cryptor);

  CCHmacInit(&hmac, kCCHmacAlgSHA256, mac_key, sizeof(mac_key));
  CCHmacUpdate(&hmac, prefix_bytes, prefix_len);
  CCHmacUpdate(&hmac, ciphertext, sizeof(plaintext));
  CCHmacFinal(&hmac, tag);

  CCHmacInit(&hmac, kCCHmacAlgSHA256, mac_key, sizeof(mac_key));
  CCHmacUpdate(&hmac, prefix_bytes, prefix_len);
  CCHmacUpdate(&hmac, ciphertext, sizeof(plaintext));
  CCHmacFinal(&hmac, actual_tag);
  if (!constant_time_eq(tag, actual_tag, sizeof(tag))) {
    fail_msg("selftest tag mismatch");
  }

  cryptor = create_ctr_cryptor(kCCDecrypt, enc_key, hdr.iv);
  if (CCCryptorUpdate(cryptor,
                      ciphertext,
                      sizeof(plaintext),
                      decrypted,
                      sizeof(decrypted),
                      &produced) != kCCSuccess ||
      produced != sizeof(plaintext)) {
    CCCryptorRelease(cryptor);
    fail_msg("selftest decryption failed");
  }
  CCCryptorRelease(cryptor);
  if (memcmp(decrypted, plaintext, sizeof(plaintext)) != 0) {
    fail_msg("selftest round-trip mismatch");
  }

  fill_header(&legacy_hdr, DEFAULT_ITERATIONS, VERSION_V3);
  serialize_header_v3(&legacy_hdr, legacy_header);
  parse_header_v3(legacy_header, &legacy_hdr);

  derive_keys("wrong password", hdr.salt, hdr.iterations, wrong_enc_key, wrong_mac_key);
  CCHmacInit(&hmac, kCCHmacAlgSHA256, wrong_mac_key, sizeof(wrong_mac_key));
  CCHmacUpdate(&hmac, prefix_bytes, prefix_len);
  CCHmacUpdate(&hmac, ciphertext, sizeof(plaintext));
  CCHmacFinal(&hmac, actual_tag);
  if (constant_time_eq(tag, actual_tag, sizeof(tag))) {
    fail_msg("selftest wrong-password case did not fail");
  }

  ciphertext[0] ^= 0x01u;
  CCHmacInit(&hmac, kCCHmacAlgSHA256, mac_key, sizeof(mac_key));
  CCHmacUpdate(&hmac, prefix_bytes, prefix_len);
  CCHmacUpdate(&hmac, ciphertext, sizeof(plaintext));
  CCHmacFinal(&hmac, actual_tag);
  ciphertext[0] ^= 0x01u;
  if (constant_time_eq(tag, actual_tag, sizeof(tag))) {
    fail_msg("selftest tamper detection failed");
  }

  secure_release_buffer(enc_key, sizeof(enc_key));
  secure_release_buffer(mac_key, sizeof(mac_key));
  secure_release_buffer(wrong_enc_key, sizeof(wrong_enc_key));
  secure_release_buffer(wrong_mac_key, sizeof(wrong_mac_key));
  free(prefix_bytes);
}

static void selftest_command(void) {
  selftest_v3();
  puts("selftest: ok");
}

int main(int argc, char **argv) {
  const char *command;
  const char *input_path = NULL;
  const char *output_path = NULL;
  uint32_t iterations = DEFAULT_ITERATIONS;
  Options opts = {0, 0, 1, 0, NULL, NULL};
  int i;
  char *end = NULL;
  unsigned long parsed;

  if (argc < 2) {
    usage(stderr, 2);
  }

  if (strcmp(argv[1], "-h") == 0 ||
      strcmp(argv[1], "--help") == 0 ||
      strcmp(argv[1], "help") == 0) {
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
      parsed = strtoul(argv[i], &end, 10);
      if (errno != 0 || end == argv[i] || *end != '\0' || parsed > UINT32_MAX) {
        fail_msg("invalid iteration count");
      }
      iterations = (uint32_t)parsed;
    } else if (strcmp(argv[i], "-f") == 0) {
      opts.force = 1;
    } else if (strcmp(argv[i], "--stdout") == 0) {
      opts.allow_stdout = 1;
      output_path = "-";
    } else if (strcmp(argv[i], "--json") == 0) {
      opts.info_json = 1;
    } else if (strcmp(argv[i], "--no-tty") == 0) {
      opts.require_tty = 0;
    } else if (strcmp(argv[i], "--passphrase-keychain-service") == 0) {
      if (++i >= argc) {
        usage(stderr, 2);
      }
      opts.keychain_service = argv[i];
    } else if (strcmp(argv[i], "--passphrase-keychain-account") == 0) {
      if (++i >= argc) {
        usage(stderr, 2);
      }
      opts.keychain_account = argv[i];
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
  if (strcmp(command, "info") == 0) {
    info_command(input_path, &opts);
    return 0;
  }
  if (strcmp(command, "syncdir") == 0) {
    syncdir_command(input_path, output_path, iterations, &opts);
    return 0;
  }
  if (strcmp(command, "restoredir") == 0) {
    restoredir_command(input_path, output_path, &opts);
    return 0;
  }
  if (strcmp(command, "selftest") == 0) {
    selftest_command();
    return 0;
  }

  usage(stderr, 2);
}
