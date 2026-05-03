#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SHAMIR_VERSION "0.1.0"
#define SHARE_PREFIX "sss1"

typedef struct {
  uint8_t x;
  unsigned int threshold;
  uint8_t *data;
  size_t data_len;
} Share;

typedef struct {
  Share *items;
  size_t count;
} ShareList;

static void usage(FILE *stream, int exit_code) {
  fprintf(stream,
          "shamir %s - small Shamir's Secret Sharing helper\n\n"
          "Usage:\n"
          "  shamir split -t THRESHOLD -n SHARES [-s TEXT | -x HEX | -i FILE]\n"
          "  shamir combine [--hex] SHARE [SHARE ...]\n"
          "  shamir combine [--hex] < shares.txt\n"
          "  shamir selftest\n\n"
          "Notes:\n"
          "  - shares are printed as %s:THRESHOLD:INDEX:HEXDATA\n"
          "  - use stdin instead of -s for sensitive secrets when possible\n"
          "  - combine writes raw bytes by default; use --hex for hex output\n",
          SHAMIR_VERSION,
          SHARE_PREFIX);
  exit(exit_code);
}

static void fail_msg(const char *msg) {
  fprintf(stderr, "shamir: %s\n", msg);
  exit(1);
}

static void fail_errno(const char *msg) {
  fprintf(stderr, "shamir: %s: %s\n", msg, strerror(errno));
  exit(1);
}

static void *xmalloc(size_t size) {
  void *ptr = malloc(size);

  if (ptr == NULL) {
    fail_msg("out of memory");
  }
  return ptr;
}

static void *xrealloc(void *ptr, size_t size) {
  void *next = realloc(ptr, size);

  if (next == NULL) {
    fail_msg("out of memory");
  }
  return next;
}

static char *xstrdup(const char *src) {
  size_t len = strlen(src) + 1u;
  char *dst = xmalloc(len);

  memcpy(dst, src, len);
  return dst;
}

static void secure_bzero(void *ptr, size_t len) {
  volatile unsigned char *p = (volatile unsigned char *)ptr;

  while (len-- > 0u) {
    *p++ = 0;
  }
}

static uint8_t gf256_mul(uint8_t left, uint8_t right) {
  uint8_t product = 0;
  unsigned int i;

  for (i = 0; i < 8u; ++i) {
    if ((right & 1u) != 0u) {
      product ^= left;
    }

    if ((left & 0x80u) != 0u) {
      left = (uint8_t)((left << 1u) ^ 0x1bu);
    } else {
      left <<= 1u;
    }
    right >>= 1u;
  }

  return product;
}

static uint8_t gf256_pow(uint8_t base, unsigned int exponent) {
  uint8_t result = 1u;

  while (exponent > 0u) {
    if ((exponent & 1u) != 0u) {
      result = gf256_mul(result, base);
    }
    exponent >>= 1u;
    if (exponent > 0u) {
      base = gf256_mul(base, base);
    }
  }

  return result;
}

static uint8_t gf256_inv(uint8_t value) {
  if (value == 0u) {
    fail_msg("invalid share value");
  }
  return gf256_pow(value, 254u);
}

static uint8_t gf256_div(uint8_t numerator, uint8_t denominator) {
  if (numerator == 0u) {
    return 0u;
  }
  return gf256_mul(numerator, gf256_inv(denominator));
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

static char hex_digit(unsigned int value) {
  return (char)(value < 10u ? ('0' + value) : ('a' + (value - 10u)));
}

static char *hex_encode_alloc(const uint8_t *src, size_t len) {
  char *dst = xmalloc((len * 2u) + 1u);
  size_t i;

  for (i = 0; i < len; ++i) {
    dst[i * 2u] = hex_digit((unsigned int)(src[i] >> 4));
    dst[(i * 2u) + 1u] = hex_digit((unsigned int)(src[i] & 0x0fu));
  }
  dst[len * 2u] = '\0';
  return dst;
}

static uint8_t *hex_decode_alloc(const char *src, size_t *len_out) {
  size_t src_len = strlen(src);
  uint8_t *dst;
  size_t i;

  if ((src_len % 2u) != 0u) {
    fail_msg("hex input must have an even number of characters");
  }
  if (src_len == 0u) {
    fail_msg("secret must not be empty");
  }

  dst = xmalloc(src_len / 2u);
  for (i = 0; i < src_len; i += 2u) {
    int hi = hex_value(src[i]);
    int lo = hex_value(src[i + 1u]);

    if (hi < 0 || lo < 0) {
      free(dst);
      fail_msg("hex input contains non-hex characters");
    }
    dst[i / 2u] = (uint8_t)((hi << 4) | lo);
  }

  *len_out = src_len / 2u;
  return dst;
}

static bool parse_uint_arg(const char *value, unsigned long *out) {
  char *end = NULL;

  errno = 0;
  *out = strtoul(value, &end, 10);
  return errno == 0 && end != value && *end == '\0';
}

static void random_bytes(void *buf, size_t len) {
  int fd = open("/dev/urandom", O_RDONLY);
  uint8_t *out = (uint8_t *)buf;
  size_t offset = 0u;

  if (fd < 0) {
    fail_errno("open /dev/urandom");
  }

  while (offset < len) {
    ssize_t nread = read(fd, out + offset, len - offset);

    if (nread < 0) {
      close(fd);
      fail_errno("read /dev/urandom");
    }
    if (nread == 0) {
      close(fd);
      fail_msg("short read from /dev/urandom");
    }
    offset += (size_t)nread;
  }

  close(fd);
}

static uint8_t *read_stream_all(FILE *fp, size_t *len_out, const char *label) {
  uint8_t *buf = NULL;
  size_t len = 0u;
  size_t cap = 0u;

  for (;;) {
    if (len == cap) {
      size_t next_cap = cap == 0u ? 1024u : cap * 2u;

      buf = xrealloc(buf, next_cap);
      cap = next_cap;
    }

    {
      size_t nread = fread(buf + len, 1, cap - len, fp);
      len += nread;

      if (nread == 0u) {
        if (ferror(fp)) {
          free(buf);
          fail_errno(label);
        }
        break;
      }
    }
  }

  if (len == 0u) {
    free(buf);
    fail_msg("secret must not be empty");
  }

  *len_out = len;
  return buf;
}

static uint8_t *read_file_all(const char *path, size_t *len_out) {
  FILE *fp = fopen(path, "rb");
  uint8_t *data;

  if (fp == NULL) {
    fail_errno(path);
  }
  data = read_stream_all(fp, len_out, path);
  fclose(fp);
  return data;
}

static uint8_t evaluate_polynomial(const uint8_t *coeffs, unsigned int coeff_count, uint8_t x) {
  int i;
  uint8_t result = 0u;

  for (i = (int)coeff_count - 1; i >= 0; --i) {
    result = gf256_mul(result, x);
    result ^= coeffs[i];
  }

  return result;
}

static uint8_t *split_secret(const uint8_t *secret,
                             size_t secret_len,
                             unsigned int threshold,
                             unsigned int share_count) {
  uint8_t *share_matrix = xmalloc(secret_len * share_count);
  uint8_t *coeffs = xmalloc(threshold);
  size_t byte_index;

  for (byte_index = 0u; byte_index < secret_len; ++byte_index) {
    unsigned int share_index;

    coeffs[0] = secret[byte_index];
    if (threshold > 1u) {
      random_bytes(coeffs + 1u, threshold - 1u);
    }

    for (share_index = 0u; share_index < share_count; ++share_index) {
      uint8_t x = (uint8_t)(share_index + 1u);

      share_matrix[(share_index * secret_len) + byte_index] =
        evaluate_polynomial(coeffs, threshold, x);
    }
  }

  secure_bzero(coeffs, threshold);
  free(coeffs);
  return share_matrix;
}

static void emit_shares(const uint8_t *share_matrix,
                        size_t secret_len,
                        unsigned int threshold,
                        unsigned int share_count) {
  unsigned int i;

  for (i = 0u; i < share_count; ++i) {
    const uint8_t *share_bytes = share_matrix + (i * secret_len);
    char *hex = hex_encode_alloc(share_bytes, secret_len);

    printf("%s:%u:%u:%s\n", SHARE_PREFIX, threshold, i + 1u, hex);
    free(hex);
  }
}

static void free_share(Share *share) {
  if (share->data != NULL) {
    secure_bzero(share->data, share->data_len);
    free(share->data);
    share->data = NULL;
  }
}

static void free_share_list(ShareList *list) {
  size_t i;

  for (i = 0u; i < list->count; ++i) {
    free_share(&list->items[i]);
  }
  free(list->items);
  list->items = NULL;
  list->count = 0u;
}

static Share parse_share_text(const char *text) {
  char *copy = xstrdup(text);
  char *prefix;
  char *threshold_text;
  char *index_text;
  char *hex_text;
  char *save = NULL;
  unsigned long parsed = 0u;
  Share share;

  memset(&share, 0, sizeof(share));
  prefix = strtok_r(copy, ":", &save);
  threshold_text = strtok_r(NULL, ":", &save);
  index_text = strtok_r(NULL, ":", &save);
  hex_text = strtok_r(NULL, ":", &save);

  if (prefix == NULL || threshold_text == NULL || index_text == NULL || hex_text == NULL ||
      strtok_r(NULL, ":", &save) != NULL) {
    free(copy);
    fail_msg("invalid share format");
  }
  if (strcmp(prefix, SHARE_PREFIX) != 0) {
    free(copy);
    fail_msg("unsupported share format");
  }
  if (!parse_uint_arg(threshold_text, &parsed) || parsed < 2u || parsed > 255u) {
    free(copy);
    fail_msg("invalid share threshold");
  }
  share.threshold = (unsigned int)parsed;
  if (!parse_uint_arg(index_text, &parsed) || parsed == 0u || parsed > 255u) {
    free(copy);
    fail_msg("invalid share index");
  }
  share.x = (uint8_t)parsed;
  share.data = hex_decode_alloc(hex_text, &share.data_len);

  free(copy);
  return share;
}

static void append_share(ShareList *list, Share share) {
  list->items = xrealloc(list->items, sizeof(Share) * (list->count + 1u));
  list->items[list->count++] = share;
}

static void read_shares_from_stdin(ShareList *list) {
  char *line = NULL;
  size_t cap = 0u;

  for (;;) {
    ssize_t nread = getline(&line, &cap, stdin);

    if (nread < 0) {
      if (ferror(stdin)) {
        free(line);
        fail_errno("stdin");
      }
      break;
    }

    while (nread > 0 && (line[nread - 1] == '\n' || line[nread - 1] == '\r')) {
      line[--nread] = '\0';
    }
    if (nread == 0) {
      continue;
    }

    append_share(list, parse_share_text(line));
  }

  free(line);
}

static uint8_t interpolate_secret_byte(const ShareList *shares, size_t byte_index) {
  size_t i;
  uint8_t result = 0u;

  for (i = 0u; i < shares->count; ++i) {
    size_t j;
    uint8_t basis = 1u;

    for (j = 0u; j < shares->count; ++j) {
      uint8_t numerator;
      uint8_t denominator;

      if (i == j) {
        continue;
      }

      numerator = shares->items[j].x;
      denominator = (uint8_t)(shares->items[j].x ^ shares->items[i].x);
      basis = gf256_mul(basis, gf256_div(numerator, denominator));
    }

    result ^= gf256_mul(shares->items[i].data[byte_index], basis);
  }

  return result;
}

static uint8_t *combine_shares(const ShareList *shares, size_t *secret_len_out) {
  bool seen[256] = {false};
  unsigned int threshold;
  size_t secret_len;
  uint8_t *secret;
  size_t i;

  if (shares->count == 0u) {
    fail_msg("no shares provided");
  }

  threshold = shares->items[0].threshold;
  secret_len = shares->items[0].data_len;
  for (i = 0u; i < shares->count; ++i) {
    if (shares->items[i].threshold != threshold) {
      fail_msg("share thresholds do not match");
    }
    if (shares->items[i].data_len != secret_len) {
      fail_msg("share lengths do not match");
    }
    if (seen[shares->items[i].x]) {
      fail_msg("duplicate share index");
    }
    seen[shares->items[i].x] = true;
  }
  if (shares->count < (size_t)threshold) {
    fail_msg("not enough shares to meet the threshold");
  }

  secret = xmalloc(secret_len);
  for (i = 0u; i < secret_len; ++i) {
    secret[i] = interpolate_secret_byte(shares, i);
  }

  *secret_len_out = secret_len;
  return secret;
}

static void write_hex_output(const uint8_t *secret, size_t secret_len) {
  char *hex = hex_encode_alloc(secret, secret_len);

  puts(hex);
  free(hex);
}

static void split_command(int argc, char **argv) {
  const char *text_secret = NULL;
  const char *hex_secret = NULL;
  const char *input_path = NULL;
  uint8_t *secret = NULL;
  uint8_t *share_matrix = NULL;
  size_t secret_len = 0u;
  unsigned long parsed = 0u;
  unsigned int threshold = 0u;
  unsigned int share_count = 0u;
  int i;

  for (i = 2; i < argc; ++i) {
    if (strcmp(argv[i], "-t") == 0) {
      if (++i >= argc || !parse_uint_arg(argv[i], &parsed)) {
        usage(stderr, 2);
      }
      threshold = (unsigned int)parsed;
    } else if (strcmp(argv[i], "-n") == 0) {
      if (++i >= argc || !parse_uint_arg(argv[i], &parsed)) {
        usage(stderr, 2);
      }
      share_count = (unsigned int)parsed;
    } else if (strcmp(argv[i], "-s") == 0) {
      if (++i >= argc) {
        usage(stderr, 2);
      }
      text_secret = argv[i];
    } else if (strcmp(argv[i], "-x") == 0) {
      if (++i >= argc) {
        usage(stderr, 2);
      }
      hex_secret = argv[i];
    } else if (strcmp(argv[i], "-i") == 0) {
      if (++i >= argc) {
        usage(stderr, 2);
      }
      input_path = argv[i];
    } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      usage(stdout, 0);
    } else {
      usage(stderr, 2);
    }
  }

  if (threshold < 2u || threshold > 255u) {
    fail_msg("threshold must be between 2 and 255");
  }
  if (share_count < threshold || share_count > 255u) {
    fail_msg("share count must be between threshold and 255");
  }

  if ((text_secret != NULL) + (hex_secret != NULL) + (input_path != NULL) > 1) {
    fail_msg("choose only one input source");
  }

  if (text_secret != NULL) {
    secret_len = strlen(text_secret);
    if (secret_len == 0u) {
      fail_msg("secret must not be empty");
    }
    secret = xmalloc(secret_len);
    memcpy(secret, text_secret, secret_len);
  } else if (hex_secret != NULL) {
    secret = hex_decode_alloc(hex_secret, &secret_len);
  } else if (input_path != NULL) {
    if (strcmp(input_path, "-") == 0) {
      secret = read_stream_all(stdin, &secret_len, "stdin");
    } else {
      secret = read_file_all(input_path, &secret_len);
    }
  } else {
    secret = read_stream_all(stdin, &secret_len, "stdin");
  }

  share_matrix = split_secret(secret, secret_len, threshold, share_count);
  emit_shares(share_matrix, secret_len, threshold, share_count);

  secure_bzero(secret, secret_len);
  secure_bzero(share_matrix, secret_len * share_count);
  free(secret);
  free(share_matrix);
}

static void combine_command(int argc, char **argv) {
  ShareList shares = {0};
  bool hex_output = false;
  uint8_t *secret;
  size_t secret_len;
  int i;

  for (i = 2; i < argc; ++i) {
    if (strcmp(argv[i], "--hex") == 0) {
      hex_output = true;
    } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      usage(stdout, 0);
    } else {
      append_share(&shares, parse_share_text(argv[i]));
    }
  }

  if (shares.count == 0u) {
    read_shares_from_stdin(&shares);
  }

  secret = combine_shares(&shares, &secret_len);
  if (hex_output) {
    write_hex_output(secret, secret_len);
  } else if (fwrite(secret, 1, secret_len, stdout) != secret_len) {
    secure_bzero(secret, secret_len);
    free(secret);
    free_share_list(&shares);
    fail_errno("stdout");
  }

  secure_bzero(secret, secret_len);
  free(secret);
  free_share_list(&shares);
}

static void selftest_command(void) {
  static const uint8_t secret[] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0xa5u, 0x5au, 0xffu, 0x10u
  };
  uint8_t *share_matrix = split_secret(secret, sizeof(secret), 3u, 5u);
  ShareList shares = {0};
  uint8_t *recovered;
  size_t recovered_len;
  unsigned int indexes[] = {1u, 3u, 5u};
  size_t i;

  for (i = 0u; i < sizeof(indexes) / sizeof(indexes[0]); ++i) {
    Share share;

    memset(&share, 0, sizeof(share));
    share.x = (uint8_t)indexes[i];
    share.threshold = 3u;
    share.data_len = sizeof(secret);
    share.data = xmalloc(share.data_len);
    memcpy(share.data,
           share_matrix + ((indexes[i] - 1u) * sizeof(secret)),
           share.data_len);
    append_share(&shares, share);
  }

  recovered = combine_shares(&shares, &recovered_len);
  if (recovered_len != sizeof(secret) || memcmp(recovered, secret, sizeof(secret)) != 0) {
    secure_bzero(recovered, recovered_len);
    free(recovered);
    free_share_list(&shares);
    secure_bzero(share_matrix, sizeof(secret) * 5u);
    free(share_matrix);
    fail_msg("selftest failed");
  }

  secure_bzero(recovered, recovered_len);
  free(recovered);
  free_share_list(&shares);
  secure_bzero(share_matrix, sizeof(secret) * 5u);
  free(share_matrix);
  puts("selftest: ok");
}

int main(int argc, char **argv) {
  if (argc < 2) {
    usage(stderr, 2);
  }

  if (strcmp(argv[1], "-h") == 0 ||
      strcmp(argv[1], "--help") == 0 ||
      strcmp(argv[1], "help") == 0) {
    usage(stdout, 0);
  }

  if (strcmp(argv[1], "split") == 0) {
    split_command(argc, argv);
    return 0;
  }
  if (strcmp(argv[1], "combine") == 0) {
    combine_command(argc, argv);
    return 0;
  }
  if (strcmp(argv[1], "selftest") == 0) {
    selftest_command();
    return 0;
  }

  usage(stderr, 2);
}
