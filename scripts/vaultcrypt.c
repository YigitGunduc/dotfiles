#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <CommonCrypto/CommonRandom.h>
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
 * Single-file macOS encryption tool using only built-in system crypto:
 *   KDF:    PBKDF2-HMAC-SHA256
 *   Cipher: AES-256-CTR
 *   MAC:    HMAC-SHA256 over header || ciphertext (encrypt-then-MAC)
 *
 * File format v1 (all integers big-endian):
 *   magic[8]      = "VLTENC01"
 *   version[4]    = 1
 *   kdf_id[4]     = 1   (PBKDF2-HMAC-SHA256)
 *   cipher_id[4]  = 1   (AES-256-CTR)
 *   mac_id[4]     = 1   (HMAC-SHA256)
 *   iterations[4] = PBKDF2 iteration count
 *   salt_len[4]   = 32
 *   iv_len[4]     = 16
 *   salt[32]
 *   iv[16]
 *   ciphertext[n]
 *   tag[32]       = HMAC-SHA256(header || ciphertext)
 *
 * Recovery requirements if this source is lost:
 *   1. Read the stored salt, IV, and iteration count from the file header.
 *   2. Derive 64 bytes with PBKDF2-HMAC-SHA256(passphrase, salt, iterations).
 *   3. Split the derived bytes into:
 *        enc_key = first 32 bytes
 *        mac_key = last 32 bytes
 *   4. Verify HMAC-SHA256(mac_key, header || ciphertext) == tag.
 *   5. Decrypt ciphertext with AES-256-CTR using enc_key and IV.
 *
 * This is intentionally narrow and explicit. It is not a general-purpose crypto
 * toolkit and should not be treated as a substitute for audited standards like
 * age or GPG when those are acceptable operationally.
 */

#define MAGIC "VLTENC01"
#define MAGIC_LEN 8
#define VERSION 1u
#define KDF_ID 1u
#define CIPHER_ID 1u
#define MAC_ID 1u
#define SALT_LEN 32u
#define IV_LEN 16u
#define KEY_LEN 32u
#define DERIVED_KEY_LEN 64u
#define TAG_LEN 32u
#define HEADER_LEN (MAGIC_LEN + (7u * 4u) + SALT_LEN + IV_LEN)
#define DEFAULT_ITERATIONS 600000u
#define MIN_ITERATIONS 100000u
#define CHUNK_SIZE 65536u
#define PASS_MAX 1024u
#define MAX_RECOVERY_PATH 4096u

typedef struct {
  int force;
  int allow_stdout;
  int require_tty;
  int info_json;
  const char *recovery_json_path;
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
} VaultHeader;

static void secure_bzero(void *ptr, size_t len) {
  volatile unsigned char *p = (volatile unsigned char *)ptr;
  while (len-- > 0) {
    *p++ = 0;
  }
}

static void usage(FILE *stream, int exit_code) {
  fprintf(stream,
          "Usage:\n"
          "  vaultcrypt enc -i INPUT [-o OUTPUT] [-n ITERATIONS] [-f] [--recovery-json PATH]\n"
          "  vaultcrypt dec -i INPUT [-o OUTPUT|-] [-f] [--stdout]\n"
          "  vaultcrypt info -i INPUT [--json]\n"
          "  vaultcrypt selftest\n"
          "\n"
          "Notes:\n"
          "  - macOS only: uses built-in CommonCrypto.\n"
          "  - enc prompts twice for a passphrase.\n"
          "  - dec prompts once and verifies integrity before releasing plaintext.\n"
          "  - enc OUTPUT defaults to INPUT.vlt.\n"
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

static void derive_keys(const char *passphrase,
                        const uint8_t salt[SALT_LEN],
                        uint32_t iterations,
                        uint8_t enc_key[KEY_LEN],
                        uint8_t mac_key[KEY_LEN]) {
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

  memcpy(enc_key, derived, KEY_LEN);
  memcpy(mac_key, derived + KEY_LEN, KEY_LEN);
  secure_bzero(derived, sizeof(derived));
}

static void fill_header(VaultHeader *hdr, uint32_t iterations) {
  hdr->version = VERSION;
  hdr->kdf_id = KDF_ID;
  hdr->cipher_id = CIPHER_ID;
  hdr->mac_id = MAC_ID;
  hdr->iterations = iterations;
  hdr->salt_len = SALT_LEN;
  hdr->iv_len = IV_LEN;
  random_bytes(hdr->salt, sizeof(hdr->salt));
  random_bytes(hdr->iv, sizeof(hdr->iv));
}

static void serialize_header(const VaultHeader *hdr, uint8_t out[HEADER_LEN]) {
  memcpy(out, MAGIC, MAGIC_LEN);
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

static void parse_header(const uint8_t in[HEADER_LEN], VaultHeader *hdr) {
  if (memcmp(in, MAGIC, MAGIC_LEN) != 0) {
    fail_msg("file does not start with a vaultcrypt header");
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

  if (hdr->version != VERSION || hdr->kdf_id != KDF_ID ||
      hdr->cipher_id != CIPHER_ID || hdr->mac_id != MAC_ID) {
    fail_msg("unsupported file format parameters");
  }
  if (hdr->salt_len != SALT_LEN || hdr->iv_len != IV_LEN) {
    fail_msg("unsupported salt or IV size in header");
  }
  if (hdr->iterations < MIN_ITERATIONS) {
    fail_msg("stored PBKDF2 iteration count is below the supported minimum");
  }
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
                                       const uint8_t key[KEY_LEN],
                                       const uint8_t iv[IV_LEN]) {
  CCCryptorRef cryptor = NULL;
  CCCryptorStatus status;

  status = CCCryptorCreateWithMode(op,
                                   kCCModeCTR,
                                   kCCAlgorithmAES,
                                   ccNoPadding,
                                   iv,
                                   key,
                                   KEY_LEN,
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

static void write_recovery_json(const char *json_path,
                                const char *ciphertext_path,
                                const VaultHeader *hdr) {
  FILE *fp;
  char *temp_path = NULL;

  if (json_path == NULL) {
    return;
  }
  if (strlen(json_path) >= MAX_RECOVERY_PATH) {
    fail_msg("recovery JSON path is too long");
  }

  fp = open_output_file_strict(json_path, 1, &temp_path);
  fprintf(fp,
          "{\n"
          "  \"tool\": \"vaultcrypt\",\n"
          "  \"format\": \"VLTENC01\",\n"
          "  \"ciphertext\": \"%s\",\n"
          "  \"kdf\": \"PBKDF2-HMAC-SHA256\",\n"
          "  \"cipher\": \"AES-256-CTR\",\n"
          "  \"mac\": \"HMAC-SHA256\",\n"
          "  \"iterations\": %u,\n"
          "  \"salt_len\": %u,\n"
          "  \"iv_len\": %u,\n"
          "  \"recovery\": [\n"
          "    \"Read salt, IV, and iteration count from the file header.\",\n"
          "    \"Derive 64 bytes with PBKDF2-HMAC-SHA256(passphrase, salt, iterations).\",\n"
          "    \"Split into enc_key=first32 and mac_key=last32.\",\n"
          "    \"Verify HMAC-SHA256(mac_key, header || ciphertext) against tag.\",\n"
          "    \"Decrypt ciphertext with AES-256-CTR using enc_key and IV.\"\n"
          "  ]\n"
          "}\n",
          ciphertext_path,
          hdr->iterations,
          hdr->salt_len,
          hdr->iv_len);
  finalize_output_file(fp, temp_path, json_path);
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
  uint8_t enc_key[KEY_LEN];
  uint8_t mac_key[KEY_LEN];
  uint8_t header_bytes[HEADER_LEN];
  uint8_t inbuf[CHUNK_SIZE];
  uint8_t outbuf[CHUNK_SIZE + 32];
  uint8_t tag[TAG_LEN];
  VaultHeader hdr;
  CCCryptorRef cryptor = NULL;
  CCHmacContext hmac;
  size_t nread;

  memset(enc_key, 0, sizeof(enc_key));
  memset(mac_key, 0, sizeof(mac_key));

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
  fill_header(&hdr, iterations);
  serialize_header(&hdr, header_bytes);
  derive_keys(passphrase, hdr.salt, hdr.iterations, enc_key, mac_key);
  cryptor = create_ctr_cryptor(kCCEncrypt, enc_key, hdr.iv);
  lock_memory_best_effort(enc_key, sizeof(enc_key));
  lock_memory_best_effort(mac_key, sizeof(mac_key));

  if (strcmp(input_path, "-") == 0) {
    in = stdin;
  } else {
    in = open_input_file(input_path);
  }
  out = open_output_temp(output_path, &temp_path, opts->force);

  write_exact(out, header_bytes, sizeof(header_bytes), "write header");
  CCHmacInit(&hmac, kCCHmacAlgSHA256, mac_key, KEY_LEN);
  CCHmacUpdate(&hmac, header_bytes, sizeof(header_bytes));

  while ((nread = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
    size_t produced = 0;
    CCCryptorStatus status;

    status = CCCryptorUpdate(cryptor,
                             inbuf,
                             nread,
                             outbuf,
                             sizeof(outbuf),
                             &produced);
    if (status != kCCSuccess) {
      fail_msg("encryption failed");
    }
    if (produced > 0) {
      CCHmacUpdate(&hmac, outbuf, produced);
      write_exact(out, outbuf, produced, "write ciphertext");
    }
  }
  if (ferror(in)) {
    fail_errno("read input");
  }

  {
    size_t produced = 0;
    CCCryptorStatus status = CCCryptorFinal(cryptor,
                                            outbuf,
                                            sizeof(outbuf),
                                            &produced);
    if (status != kCCSuccess) {
      fail_msg("final encryption step failed");
    }
    if (produced > 0) {
      CCHmacUpdate(&hmac, outbuf, produced);
      write_exact(out, outbuf, produced, "write final ciphertext");
    }
  }

  CCHmacFinal(&hmac, tag);
  write_exact(out, tag, sizeof(tag), "write tag");
  finalize_output_file(out, temp_path, output_path);
  out = NULL;
  temp_path = NULL;
  write_recovery_json(opts->recovery_json_path, output_path, &hdr);

  if (in != NULL && in != stdin) {
    fclose(in);
  }
  CCCryptorRelease(cryptor);
  secure_release_buffer(enc_key, sizeof(enc_key));
  secure_release_buffer(mac_key, sizeof(mac_key));
  secure_release_buffer(passphrase, strlen(passphrase));
  free(passphrase);
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

static void decrypt_command(const char *input_path, const char *output_path, const Options *opts) {
  FILE *in = NULL;
  FILE *tmp = NULL;
  char *temp_path = NULL;
  char *passphrase = NULL;
  uint8_t header_bytes[HEADER_LEN];
  uint8_t expected_tag[TAG_LEN];
  uint8_t actual_tag[TAG_LEN];
  uint8_t enc_key[KEY_LEN];
  uint8_t mac_key[KEY_LEN];
  uint8_t inbuf[CHUNK_SIZE];
  uint8_t outbuf[CHUNK_SIZE + 32];
  VaultHeader hdr;
  CCCryptorRef cryptor = NULL;
  CCHmacContext hmac;
  uint64_t total_size;
  uint64_t ciphertext_len;
  uint64_t remaining;

  memset(enc_key, 0, sizeof(enc_key));
  memset(mac_key, 0, sizeof(mac_key));

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
  if (total_size < HEADER_LEN + TAG_LEN) {
    fail_msg("file is too small to be a vaultcrypt ciphertext");
  }
  ciphertext_len = total_size - HEADER_LEN - TAG_LEN;

  in = open_input_file(input_path);
  read_exact(in, header_bytes, sizeof(header_bytes), "read header");
  parse_header(header_bytes, &hdr);

  passphrase = prompt_passphrase("Passphrase: ", 0, opts->require_tty);
  derive_keys(passphrase, hdr.salt, hdr.iterations, enc_key, mac_key);
  cryptor = create_ctr_cryptor(kCCDecrypt, enc_key, hdr.iv);
  lock_memory_best_effort(enc_key, sizeof(enc_key));
  lock_memory_best_effort(mac_key, sizeof(mac_key));

  CCHmacInit(&hmac, kCCHmacAlgSHA256, mac_key, KEY_LEN);
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
    tmp = NULL;
    temp_path = NULL;
  } else {
    copy_file_to_stream(tmp, stdout);
    fclose(tmp);
    tmp = NULL;
  }

  fclose(in);
  CCCryptorRelease(cryptor);
  secure_release_buffer(enc_key, sizeof(enc_key));
  secure_release_buffer(mac_key, sizeof(mac_key));
  secure_release_buffer(passphrase, strlen(passphrase));
  free(passphrase);
}

static void info_command(const char *input_path, const Options *opts) {
  FILE *in;
  uint8_t header_bytes[HEADER_LEN];
  VaultHeader hdr;

  if (input_path == NULL || strcmp(input_path, "-") == 0) {
    fail_msg("info requires a regular input file");
  }

  in = open_input_file(input_path);
  read_exact(in, header_bytes, sizeof(header_bytes), "read header");
  fclose(in);
  parse_header(header_bytes, &hdr);

  if (opts->info_json) {
    printf("{\n"
           "  \"file\": \"%s\",\n"
           "  \"format\": \"VLTENC01\",\n"
           "  \"kdf\": \"PBKDF2-HMAC-SHA256\",\n"
           "  \"cipher\": \"AES-256-CTR\",\n"
           "  \"mac\": \"HMAC-SHA256 (encrypt-then-MAC)\",\n"
           "  \"iterations\": %u,\n"
           "  \"salt_len\": %u,\n"
           "  \"iv_len\": %u\n"
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

static void selftest_command(void) {
  static const char plaintext[] = "vaultcrypt self-test payload\nline2\n";
  static const char passphrase[] = "correct horse battery staple selftest";
  VaultHeader hdr;
  uint8_t header_bytes[HEADER_LEN];
  uint8_t enc_key[KEY_LEN];
  uint8_t mac_key[KEY_LEN];
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

  fill_header(&hdr, DEFAULT_ITERATIONS);
  serialize_header(&hdr, header_bytes);
  derive_keys(passphrase, hdr.salt, hdr.iterations, enc_key, mac_key);

  enc = create_ctr_cryptor(kCCEncrypt, enc_key, hdr.iv);
  if (CCCryptorUpdate(enc, plaintext, sizeof(plaintext), cipherbuf, sizeof(cipherbuf), &cipher_len) != kCCSuccess) {
    fail_msg("selftest encryption failed");
  }
  CCCryptorRelease(enc);

  CCHmacInit(&hmac, kCCHmacAlgSHA256, mac_key, KEY_LEN);
  CCHmacUpdate(&hmac, header_bytes, sizeof(header_bytes));
  CCHmacUpdate(&hmac, cipherbuf, cipher_len);
  CCHmacFinal(&hmac, tag);

  CCHmacInit(&hmac, kCCHmacAlgSHA256, mac_key, KEY_LEN);
  CCHmacUpdate(&hmac, header_bytes, sizeof(header_bytes));
  CCHmacUpdate(&hmac, cipherbuf, cipher_len);
  CCHmacFinal(&hmac, actual_tag);
  if (!constant_time_eq(tag, actual_tag, TAG_LEN)) {
    fail_msg("selftest tag mismatch");
  }

  dec = create_ctr_cryptor(kCCDecrypt, enc_key, hdr.iv);
  if (CCCryptorUpdate(dec, cipherbuf, cipher_len, plainbuf, sizeof(plainbuf), &plain_len) != kCCSuccess) {
    fail_msg("selftest decryption failed");
  }
  CCCryptorRelease(dec);
  if (plain_len != sizeof(plaintext) || memcmp(plainbuf, plaintext, sizeof(plaintext)) != 0) {
    fail_msg("selftest round-trip mismatch");
  }

  derive_keys("wrong password", hdr.salt, hdr.iterations, enc_key, mac_key);
  CCHmacInit(&hmac, kCCHmacAlgSHA256, mac_key, KEY_LEN);
  CCHmacUpdate(&hmac, header_bytes, sizeof(header_bytes));
  CCHmacUpdate(&hmac, cipherbuf, cipher_len);
  CCHmacFinal(&hmac, actual_tag);
  if (constant_time_eq(tag, actual_tag, TAG_LEN)) {
    fail_msg("selftest wrong-password case did not fail");
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

  derive_keys(passphrase, hdr.salt, hdr.iterations, enc_key, mac_key);
  CCHmacInit(&hmac, kCCHmacAlgSHA256, mac_key, KEY_LEN);
  CCHmacUpdate(&hmac, header_bytes, sizeof(header_bytes));
  CCHmacUpdate(&hmac, cipherbuf, cipher_len);
  CCHmacFinal(&hmac, actual_tag);
  if (constant_time_eq(tag, actual_tag, TAG_LEN)) {
    fail_msg("selftest tamper detection failed");
  }

  secure_release_buffer(enc_key, sizeof(enc_key));
  secure_release_buffer(mac_key, sizeof(mac_key));
  puts("selftest: ok");
}

int main(int argc, char **argv) {
  const char *command = NULL;
  const char *input_path = NULL;
  const char *output_path = NULL;
  uint32_t iterations = DEFAULT_ITERATIONS;
  Options opts = {0, 0, 1, 0, NULL};
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
    } else if (strcmp(argv[i], "-f") == 0) {
      opts.force = 1;
    } else if (strcmp(argv[i], "--stdout") == 0) {
      opts.allow_stdout = 1;
      output_path = "-";
    } else if (strcmp(argv[i], "--json") == 0) {
      opts.info_json = 1;
    } else if (strcmp(argv[i], "--recovery-json") == 0) {
      if (++i >= argc) {
        usage(stderr, 2);
      }
      opts.recovery_json_path = argv[i];
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
