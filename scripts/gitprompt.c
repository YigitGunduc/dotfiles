#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define INDEX_SIGNATURE "DIRC"
#define HEAD_REF_PREFIX "ref: "
#define HEADS_PREFIX "refs/heads/"
#define HEX_SHORT_LEN 7

typedef struct {
  char worktree[PATH_MAX];
  char gitdir[PATH_MAX];
  char branch[PATH_MAX];
  bool detached;
  bool dirty;
} RepoInfo;

static uint32_t read_be32(const unsigned char *buf) {
  return ((uint32_t) buf[0] << 24) |
         ((uint32_t) buf[1] << 16) |
         ((uint32_t) buf[2] << 8) |
         (uint32_t) buf[3];
}

static bool is_hex_string(const char *value) {
  size_t i;
  size_t len = strlen(value);

  if (len < 40) {
    return false;
  }

  for (i = 0; i < 40; i++) {
    if (!isxdigit((unsigned char) value[i])) {
      return false;
    }
  }

  return true;
}

static void trim_line(char *line) {
  size_t len = strlen(line);
  while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
    line[--len] = '\0';
  }
}

static bool join_path(char *out, size_t out_size, const char *left,
                      const char *right) {
  if (snprintf(out, out_size, "%s/%s", left, right) >= (int) out_size) {
    return false;
  }
  return true;
}

static bool resolve_path(char *out, size_t out_size, const char *base,
                         const char *value) {
  char buffer[PATH_MAX];

  if (value[0] == '/') {
    if (realpath(value, out) != NULL) {
      return true;
    }
    return snprintf(out, out_size, "%s", value) < (int) out_size;
  }

  if (!join_path(buffer, sizeof(buffer), base, value)) {
    return false;
  }

  if (realpath(buffer, out) != NULL) {
    return true;
  }

  return snprintf(out, out_size, "%s", buffer) < (int) out_size;
}

static bool read_gitdir_file(const char *gitfile, const char *base_dir,
                             char *out, size_t out_size) {
  FILE *fp = fopen(gitfile, "r");
  char line[PATH_MAX + 16];
  const char *prefix = "gitdir: ";

  if (fp == NULL) {
    return false;
  }

  if (fgets(line, sizeof(line), fp) == NULL) {
    fclose(fp);
    return false;
  }
  fclose(fp);

  trim_line(line);
  if (strncmp(line, prefix, strlen(prefix)) != 0) {
    return false;
  }

  return resolve_path(out, out_size, base_dir, line + strlen(prefix));
}

static bool find_repo(RepoInfo *repo) {
  char current[PATH_MAX];
  char candidate[PATH_MAX];
  struct stat st;

  if (getcwd(current, sizeof(current)) == NULL) {
    return false;
  }

  for (;;) {
    if (!join_path(candidate, sizeof(candidate), current, ".git")) {
      return false;
    }

    if (lstat(candidate, &st) == 0) {
      if (S_ISDIR(st.st_mode)) {
        if (realpath(current, repo->worktree) == NULL) {
          return false;
        }
        if (realpath(candidate, repo->gitdir) == NULL) {
          return false;
        }
        return true;
      }

      if (S_ISREG(st.st_mode)) {
        if (realpath(current, repo->worktree) == NULL) {
          return false;
        }
        if (read_gitdir_file(candidate, current, repo->gitdir,
                             sizeof(repo->gitdir))) {
          return true;
        }
        return false;
      }
    }

    if (strcmp(current, "/") == 0) {
      break;
    }

    {
      char *slash = strrchr(current, '/');
      if (slash == NULL) {
        break;
      }
      if (slash == current) {
        current[1] = '\0';
      } else {
        *slash = '\0';
      }
    }
  }

  return false;
}

static bool load_head(RepoInfo *repo) {
  char head_path[PATH_MAX];
  FILE *fp;
  char line[PATH_MAX + 64];

  if (!join_path(head_path, sizeof(head_path), repo->gitdir, "HEAD")) {
    return false;
  }

  fp = fopen(head_path, "r");
  if (fp == NULL) {
    return false;
  }

  if (fgets(line, sizeof(line), fp) == NULL) {
    fclose(fp);
    return false;
  }
  fclose(fp);
  trim_line(line);

  if (strncmp(line, HEAD_REF_PREFIX, strlen(HEAD_REF_PREFIX)) == 0) {
    char *ref = line + strlen(HEAD_REF_PREFIX);
    if (strncmp(ref, HEADS_PREFIX, strlen(HEADS_PREFIX)) == 0) {
      ref += strlen(HEADS_PREFIX);
    }
    snprintf(repo->branch, sizeof(repo->branch), "%s", ref);
    repo->detached = false;
    return true;
  }

  if (is_hex_string(line)) {
    snprintf(repo->branch, sizeof(repo->branch), "detached@%.*s",
             HEX_SHORT_LEN, line);
    repo->detached = true;
    return true;
  }

  return false;
}

static bool path_has_component(const char *path, const char *name) {
  const char *segment = path;
  size_t name_len = strlen(name);

  while (*segment != '\0') {
    const char *slash = strchr(segment, '/');
    size_t len = slash == NULL ? strlen(segment) : (size_t) (slash - segment);

    if (len == name_len && strncmp(segment, name, len) == 0) {
      return true;
    }

    if (slash == NULL) {
      break;
    }
    segment = slash + 1;
  }

  return false;
}

static bool stat_matches_index(const char *path, uint32_t mode, uint32_t size,
                               uint32_t mtime_sec, uint32_t mtime_nsec) {
  struct stat st;

  if (lstat(path, &st) != 0) {
    return false;
  }

  if ((mode & 0170000U) == 0120000U) {
    if (!S_ISLNK(st.st_mode)) {
      return false;
    }
  } else if ((mode & 0170000U) == 0100000U) {
    if (!S_ISREG(st.st_mode)) {
      return false;
    }
  }

  if ((uint32_t) st.st_size != size) {
    return false;
  }

  if ((uint32_t) st.st_mtime != mtime_sec) {
    return false;
  }

#if defined(__APPLE__)
  if ((uint32_t) st.st_mtimespec.tv_nsec != mtime_nsec) {
    return false;
  }
#elif defined(st_mtim)
  if ((uint32_t) st.st_mtim.tv_nsec != mtime_nsec) {
    return false;
  }
#endif

  return true;
}

static bool repo_is_dirty(RepoInfo *repo) {
  char index_path[PATH_MAX];
  FILE *fp;
  unsigned char header[12];
  uint32_t version;
  uint32_t entries;
  uint32_t i;

  if (!join_path(index_path, sizeof(index_path), repo->gitdir, "index")) {
    return false;
  }

  fp = fopen(index_path, "rb");
  if (fp == NULL) {
    return false;
  }

  if (fread(header, 1, sizeof(header), fp) != sizeof(header)) {
    fclose(fp);
    return false;
  }

  if (memcmp(header, INDEX_SIGNATURE, 4) != 0) {
    fclose(fp);
    return false;
  }

  version = read_be32(header + 4);
  entries = read_be32(header + 8);
  if (version < 2 || version > 3) {
    fclose(fp);
    return false;
  }

  for (i = 0; i < entries; i++) {
    unsigned char entry_head[62];
    uint16_t flags;
    uint16_t stage;
    uint32_t mode;
    uint32_t mtime_sec;
    uint32_t mtime_nsec;
    uint32_t size;
    size_t path_len = 0;
    char entry_path[PATH_MAX];
    char full_path[PATH_MAX * 2];
    int ch;
    long entry_bytes;
    long padding;

    if (fread(entry_head, 1, sizeof(entry_head), fp) != sizeof(entry_head)) {
      fclose(fp);
      return false;
    }

    mtime_sec = read_be32(entry_head + 8);
    mtime_nsec = read_be32(entry_head + 12);
    mode = read_be32(entry_head + 24);
    size = read_be32(entry_head + 36);
    flags = (uint16_t) ((entry_head[60] << 8) | entry_head[61]);
    stage = (uint16_t) ((flags >> 12) & 0x3);

    for (;;) {
      ch = fgetc(fp);
      if (ch == EOF) {
        fclose(fp);
        return false;
      }
      if (ch == '\0') {
        break;
      }
      if (path_len + 1 < sizeof(entry_path)) {
        entry_path[path_len++] = (char) ch;
      }
    }
    entry_path[path_len] = '\0';

    entry_bytes = 62L + (long) path_len + 1L;
    padding = (8L - (entry_bytes % 8L)) % 8L;
    if (fseek(fp, padding, SEEK_CUR) != 0) {
      fclose(fp);
      return false;
    }

    if (stage != 0) {
      continue;
    }

    if (entry_path[0] == '\0' || path_has_component(entry_path, ".git")) {
      continue;
    }

    if (!join_path(full_path, sizeof(full_path), repo->worktree, entry_path)) {
      fclose(fp);
      return false;
    }

    if (!stat_matches_index(full_path, mode, size, mtime_sec, mtime_nsec)) {
      fclose(fp);
      return true;
    }
  }

  fclose(fp);
  return false;
}

int main(void) {
  RepoInfo repo;

  memset(&repo, 0, sizeof(repo));

  if (!find_repo(&repo)) {
    return 0;
  }

  if (!load_head(&repo)) {
    return 0;
  }

  repo.dirty = repo_is_dirty(&repo);
  printf(" (%s%s)", repo.branch, repo.dirty ? "*" : "");
  return 0;
}
