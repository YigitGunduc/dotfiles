#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>

#define FTREE_VERSION "0.1.0"

typedef enum {
  SORT_NAME = 0,
  SORT_SIZE = 1
} SortMode;

typedef struct {
  char *name;
  char *path;
  char *link_target;
  struct stat st;
  bool is_dir;
  bool is_symlink;
  bool is_executable;
} Entry;

typedef struct {
  bool show_all;
  bool dirs_only;
  bool full_path;
  bool show_permissions;
  bool show_size;
  bool show_lines;
  bool use_color;
  bool dirs_first;
  int max_depth;
  SortMode sort_mode;
  char **ignore_names;
  size_t ignore_count;
  long long dir_count;
  long long file_count;
  int error_count;
} Config;

static Config g_cfg = {
  .show_all = false,
  .dirs_only = false,
  .full_path = false,
  .show_permissions = false,
  .show_size = false,
  .show_lines = false,
  .use_color = false,
  .dirs_first = true,
  .max_depth = -1,
  .sort_mode = SORT_NAME,
  .ignore_names = NULL,
  .ignore_count = 0,
  .dir_count = 0,
  .file_count = 0,
  .error_count = 0
};

static const char *COLOR_RESET = "\033[0m";
static const char *COLOR_DIR = "\033[1;34m";
static const char *COLOR_LINK = "\033[1;36m";
static const char *COLOR_EXEC = "\033[1;32m";
static const char *COLOR_ROOT = "\033[1;35m";

static void usage(FILE *stream) {
  fprintf(stream,
          "ftree %s - a small tree-style directory viewer\n\n"
          "Usage:\n"
          "  ftree [options] [path]\n\n"
          "Options:\n"
          "  -a, --all              include hidden files and directories\n"
          "  -d, --dirs-only        show directories only\n"
          "  -f, --full-path        print full paths for entries\n"
          "  -I, --ignore LIST      ignore comma-separated basenames\n"
          "  -L, --max-depth N      recurse at most N levels\n"
          "  -p, --permissions      show rwx permissions\n"
          "  -s, --size             show entry sizes\n"
          "      --lines            count lines in regular files\n"
          "      --sort MODE        sort by 'name' or 'size'\n"
          "      --files-first      list files before directories\n"
          "      --no-color         disable color output\n"
          "      --version          print version and exit\n"
          "  -h, --help             show this help text\n\n"
          "Examples:\n"
          "  ftree\n"
          "  ftree -a -L 2 ~/Developer\n"
          "  ftree -I .git,node_modules --sort size -s\n",
          FTREE_VERSION);
}

static void *xmalloc(size_t size) {
  void *ptr = malloc(size);
  if (ptr == NULL) {
    perror("malloc");
    exit(1);
  }
  return ptr;
}

static void *xrealloc(void *ptr, size_t size) {
  void *next = realloc(ptr, size);
  if (next == NULL) {
    perror("realloc");
    exit(1);
  }
  return next;
}

static char *xstrdup(const char *src) {
  size_t len = strlen(src) + 1;
  char *dst = xmalloc(len);
  memcpy(dst, src, len);
  return dst;
}

static bool str_eq(const char *left, const char *right) {
  return strcmp(left, right) == 0;
}

static const char *base_name_from_path(const char *path) {
  const char *slash = strrchr(path, '/');
  if (slash == NULL) {
    return path;
  }
  if (*(slash + 1) == '\0' && slash != path) {
    while (slash > path && *slash == '/') {
      slash--;
    }
    while (slash > path && *(slash - 1) != '/') {
      slash--;
    }
    return slash;
  }
  return slash + 1;
}

static char *join_path(const char *base, const char *name) {
  size_t base_len = strlen(base);
  size_t name_len = strlen(name);
  bool needs_sep = !(base_len > 0 && base[base_len - 1] == '/');
  size_t total = base_len + (needs_sep ? 1 : 0) + name_len + 1;
  char *path = xmalloc(total);
  snprintf(path, total, "%s%s%s", base, needs_sep ? "/" : "", name);
  return path;
}

static char *absolute_path(const char *path) {
  char resolved[PATH_MAX];

  if (realpath(path, resolved) != NULL) {
    return xstrdup(resolved);
  }

  if (path[0] == '/') {
    return xstrdup(path);
  }

  if (getcwd(resolved, sizeof(resolved)) == NULL) {
    perror("getcwd");
    exit(1);
  }

  return join_path(resolved, path);
}

static void append_ignore_name(const char *name) {
  g_cfg.ignore_names = xrealloc(g_cfg.ignore_names,
                                sizeof(char *) * (g_cfg.ignore_count + 1));
  g_cfg.ignore_names[g_cfg.ignore_count++] = xstrdup(name);
}

static void parse_ignore_list(const char *value) {
  char *copy = xstrdup(value);
  char *token = strtok(copy, ",");

  while (token != NULL) {
    while (*token != '\0' && isspace((unsigned char) *token)) {
      token++;
    }
    if (*token != '\0') {
      char *end = token + strlen(token) - 1;
      while (end > token && isspace((unsigned char) *end)) {
        *end-- = '\0';
      }
      if (*token != '\0') {
        append_ignore_name(token);
      }
    }
    token = strtok(NULL, ",");
  }

  free(copy);
}

static bool is_ignored(const char *name) {
  size_t i;

  if (!g_cfg.show_all && name[0] == '.') {
    return true;
  }

  for (i = 0; i < g_cfg.ignore_count; i++) {
    if (str_eq(name, g_cfg.ignore_names[i])) {
      return true;
    }
  }

  return false;
}

static void permissions_to_string(mode_t mode, char out[11]) {
  out[0] = S_ISDIR(mode) ? 'd' : S_ISLNK(mode) ? 'l' : '-';
  out[1] = (mode & S_IRUSR) ? 'r' : '-';
  out[2] = (mode & S_IWUSR) ? 'w' : '-';
  out[3] = (mode & S_IXUSR) ? 'x' : '-';
  out[4] = (mode & S_IRGRP) ? 'r' : '-';
  out[5] = (mode & S_IWGRP) ? 'w' : '-';
  out[6] = (mode & S_IXGRP) ? 'x' : '-';
  out[7] = (mode & S_IROTH) ? 'r' : '-';
  out[8] = (mode & S_IWOTH) ? 'w' : '-';
  out[9] = (mode & S_IXOTH) ? 'x' : '-';
  out[10] = '\0';
}

static void human_size(off_t size, char *buf, size_t buf_size) {
  const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
  double value = (double) size;
  size_t unit = 0;

  while (value >= 1024.0 && unit < (sizeof(units) / sizeof(units[0])) - 1) {
    value /= 1024.0;
    unit++;
  }

  if (unit == 0) {
    snprintf(buf, buf_size, "%lld %s", (long long) size, units[unit]);
  } else {
    snprintf(buf, buf_size, "%.1f %s", value, units[unit]);
  }
}

static long count_lines(const char *path) {
  FILE *file = fopen(path, "r");
  int ch;
  long lines = 0;

  if (file == NULL) {
    return -1;
  }

  while ((ch = fgetc(file)) != EOF) {
    if (ch == '\0') {
      fclose(file);
      return -1;
    }
    if (ch == '\n') {
      lines++;
    }
  }

  if (ferror(file)) {
    fclose(file);
    return -1;
  }

  fclose(file);
  return lines;
}

static char *read_link_target(const char *path, const struct stat *st) {
  size_t buf_size = (st->st_size > 0) ? (size_t) st->st_size + 1 : PATH_MAX;
  ssize_t len;
  char *buf = xmalloc(buf_size);

  len = readlink(path, buf, buf_size - 1);
  if (len < 0) {
    free(buf);
    return NULL;
  }

  buf[len] = '\0';
  return buf;
}

static int compare_entries(const void *left, const void *right) {
  const Entry *a = left;
  const Entry *b = right;

  if (g_cfg.dirs_first && a->is_dir != b->is_dir) {
    return a->is_dir ? -1 : 1;
  }

  if (g_cfg.sort_mode == SORT_SIZE && a->st.st_size != b->st.st_size) {
    if (a->st.st_size < b->st.st_size) {
      return 1;
    }
    return -1;
  }

  return strcasecmp(a->name, b->name);
}

static void free_entries(Entry *entries, size_t count) {
  size_t i;
  for (i = 0; i < count; i++) {
    free(entries[i].name);
    free(entries[i].path);
    free(entries[i].link_target);
  }
  free(entries);
}

static const char *entry_color(const Entry *entry, bool is_root) {
  if (!g_cfg.use_color) {
    return "";
  }
  if (is_root) {
    return COLOR_ROOT;
  }
  if (entry->is_symlink) {
    return COLOR_LINK;
  }
  if (entry->is_dir) {
    return COLOR_DIR;
  }
  if (entry->is_executable) {
    return COLOR_EXEC;
  }
  return "";
}

static const char *color_reset(void) {
  return g_cfg.use_color ? COLOR_RESET : "";
}

static void print_metadata(const Entry *entry) {
  bool started = false;
  char perms[11];
  char size_buf[32];

  if (!g_cfg.show_permissions && !g_cfg.show_size && !g_cfg.show_lines) {
    return;
  }

  printf(" [");

  if (g_cfg.show_permissions) {
    permissions_to_string(entry->st.st_mode, perms);
    printf("%s", perms);
    started = true;
  }

  if (g_cfg.show_size) {
    human_size(entry->st.st_size, size_buf, sizeof(size_buf));
    printf("%s%s", started ? ", " : "", size_buf);
    started = true;
  }

  if (g_cfg.show_lines) {
    long lines = -1;
    if (!entry->is_dir && !entry->is_symlink && S_ISREG(entry->st.st_mode)) {
      lines = count_lines(entry->path);
    }

    if (lines >= 0) {
      printf("%s%ld lines", started ? ", " : "", lines);
    } else {
      printf("%sline n/a", started ? ", " : "");
    }
  }

  printf("]");
}

static void print_entry_line(const Entry *entry,
                             const char *prefix,
                             bool is_last,
                             bool is_root,
                             const char *root_label) {
  const char *label;
  const char *color;

  if (is_root) {
    label = root_label;
  } else if (g_cfg.full_path) {
    label = entry->path;
  } else {
    label = entry->name;
  }

  color = entry_color(entry, is_root);

  if (!is_root) {
    printf("%s%s", prefix, is_last ? "`-- " : "|-- ");
  }

  printf("%s%s%s", color, label, color_reset());
  print_metadata(entry);

  if (entry->is_symlink && entry->link_target != NULL) {
    printf(" -> %s", entry->link_target);
  }

  putchar('\n');
}

static Entry *read_entries(const char *dir_path, size_t *out_count) {
  DIR *dir = opendir(dir_path);
  struct dirent *dp;
  Entry *entries = NULL;
  size_t count = 0;
  size_t capacity = 0;

  if (dir == NULL) {
    fprintf(stderr, "ftree: %s: %s\n", dir_path, strerror(errno));
    g_cfg.error_count++;
    *out_count = 0;
    return NULL;
  }

  while ((dp = readdir(dir)) != NULL) {
    Entry entry;

    if (str_eq(dp->d_name, ".") || str_eq(dp->d_name, "..")) {
      continue;
    }

    if (is_ignored(dp->d_name)) {
      continue;
    }

    memset(&entry, 0, sizeof(entry));
    entry.name = xstrdup(dp->d_name);
    entry.path = join_path(dir_path, dp->d_name);

    if (lstat(entry.path, &entry.st) != 0) {
      fprintf(stderr, "ftree: %s: %s\n", entry.path, strerror(errno));
      g_cfg.error_count++;
      free(entry.name);
      free(entry.path);
      continue;
    }

    entry.is_symlink = S_ISLNK(entry.st.st_mode);
    entry.is_dir = S_ISDIR(entry.st.st_mode);
    entry.is_executable = !entry.is_dir && !entry.is_symlink &&
                          (entry.st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH));

    if (entry.is_symlink) {
      entry.link_target = read_link_target(entry.path, &entry.st);
    }

    if (g_cfg.dirs_only && !entry.is_dir) {
      free(entry.name);
      free(entry.path);
      free(entry.link_target);
      continue;
    }

    if (count == capacity) {
      capacity = capacity == 0 ? 16 : capacity * 2;
      entries = xrealloc(entries, capacity * sizeof(Entry));
    }

    entries[count++] = entry;
  }

  closedir(dir);

  if (count > 1) {
    qsort(entries, count, sizeof(Entry), compare_entries);
  }

  *out_count = count;
  return entries;
}

static void walk_tree(const char *dir_path, int depth, const char *prefix) {
  Entry *entries;
  size_t count;
  size_t i;

  if (g_cfg.max_depth >= 0 && depth >= g_cfg.max_depth) {
    return;
  }

  entries = read_entries(dir_path, &count);
  if (entries == NULL) {
    return;
  }

  for (i = 0; i < count; i++) {
    Entry *entry = &entries[i];
    bool is_last = (i + 1 == count);

    print_entry_line(entry, prefix, is_last, false, NULL);

    if (entry->is_dir) {
      char *next_prefix = xmalloc(strlen(prefix) + 5);

      g_cfg.dir_count++;
      snprintf(next_prefix,
               strlen(prefix) + 5,
               "%s%s",
               prefix,
               is_last ? "    " : "|   ");

      walk_tree(entry->path, depth + 1, next_prefix);
      free(next_prefix);
    } else {
      g_cfg.file_count++;
    }
  }

  free_entries(entries, count);
}

static const char *next_value(int argc, char **argv, int *index, const char *opt) {
  if (*index + 1 >= argc) {
    fprintf(stderr, "ftree: missing value for %s\n", opt);
    exit(1);
  }
  (*index)++;
  return argv[*index];
}

static int parse_non_negative(const char *value, const char *opt) {
  char *end = NULL;
  long parsed = strtol(value, &end, 10);

  if (value[0] == '\0' || end == NULL || *end != '\0' || parsed < 0) {
    fprintf(stderr, "ftree: invalid value for %s: %s\n", opt, value);
    exit(1);
  }

  if (parsed > INT_MAX) {
    fprintf(stderr, "ftree: value too large for %s: %s\n", opt, value);
    exit(1);
  }

  return (int) parsed;
}

static void set_sort_mode(const char *value) {
  if (str_eq(value, "name")) {
    g_cfg.sort_mode = SORT_NAME;
  } else if (str_eq(value, "size")) {
    g_cfg.sort_mode = SORT_SIZE;
  } else {
    fprintf(stderr, "ftree: unsupported sort mode: %s\n", value);
    exit(1);
  }
}

static const char *match_long_option(const char *arg, const char *name) {
  size_t len = strlen(name);
  if (strncmp(arg, name, len) == 0 && arg[len] == '=') {
    return arg + len + 1;
  }
  return NULL;
}

static const char *parse_args(int argc, char **argv) {
  const char *path = ".";
  int i;

  for (i = 1; i < argc; i++) {
    const char *value;

    if (str_eq(argv[i], "--")) {
      if (i + 1 < argc) {
        path = argv[++i];
      }
      break;
    }

    if (argv[i][0] != '-' || str_eq(argv[i], "-")) {
      if (!str_eq(path, ".")) {
        fprintf(stderr, "ftree: unexpected extra path: %s\n", argv[i]);
        exit(1);
      }
      path = argv[i];
      continue;
    }

    if (str_eq(argv[i], "-a") || str_eq(argv[i], "--all")) {
      g_cfg.show_all = true;
    } else if (str_eq(argv[i], "-d") || str_eq(argv[i], "--dirs-only")) {
      g_cfg.dirs_only = true;
    } else if (str_eq(argv[i], "-f") || str_eq(argv[i], "--full-path")) {
      g_cfg.full_path = true;
    } else if (str_eq(argv[i], "-p") || str_eq(argv[i], "--permissions")) {
      g_cfg.show_permissions = true;
    } else if (str_eq(argv[i], "-s") || str_eq(argv[i], "--size")) {
      g_cfg.show_size = true;
    } else if (str_eq(argv[i], "--lines")) {
      g_cfg.show_lines = true;
    } else if (str_eq(argv[i], "--files-first")) {
      g_cfg.dirs_first = false;
    } else if (str_eq(argv[i], "--no-color")) {
      g_cfg.use_color = false;
    } else if (str_eq(argv[i], "-h") || str_eq(argv[i], "--help")) {
      usage(stdout);
      exit(0);
    } else if (str_eq(argv[i], "--version")) {
      puts("ftree " FTREE_VERSION);
      exit(0);
    } else if (str_eq(argv[i], "-I") || str_eq(argv[i], "--ignore")) {
      parse_ignore_list(next_value(argc, argv, &i, argv[i]));
    } else if ((value = match_long_option(argv[i], "--ignore")) != NULL) {
      parse_ignore_list(value);
    } else if (str_eq(argv[i], "-L") || str_eq(argv[i], "--max-depth")) {
      g_cfg.max_depth = parse_non_negative(next_value(argc, argv, &i, argv[i]),
                                           argv[i]);
    } else if ((value = match_long_option(argv[i], "--max-depth")) != NULL) {
      g_cfg.max_depth = parse_non_negative(value, "--max-depth");
    } else if (str_eq(argv[i], "--sort")) {
      set_sort_mode(next_value(argc, argv, &i, argv[i]));
    } else if ((value = match_long_option(argv[i], "--sort")) != NULL) {
      set_sort_mode(value);
    } else {
      fprintf(stderr, "ftree: unknown option: %s\n", argv[i]);
      fprintf(stderr, "Try 'ftree --help' for usage.\n");
      exit(1);
    }
  }

  return path;
}

static void free_config(void) {
  size_t i;
  for (i = 0; i < g_cfg.ignore_count; i++) {
    free(g_cfg.ignore_names[i]);
  }
  free(g_cfg.ignore_names);
}

static int print_root_and_walk(const char *path) {
  Entry root;
  const char *root_label = path;

  memset(&root, 0, sizeof(root));
  root.name = xstrdup(base_name_from_path(path));
  root.path = g_cfg.full_path ? absolute_path(path) : xstrdup(path);

  if (lstat(path, &root.st) != 0) {
    fprintf(stderr, "ftree: %s: %s\n", path, strerror(errno));
    free(root.name);
    free(root.path);
    return 1;
  }

  root.is_symlink = S_ISLNK(root.st.st_mode);
  root.is_dir = S_ISDIR(root.st.st_mode);
  root.is_executable = !root.is_dir && !root.is_symlink &&
                       (root.st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH));

  if (root.is_symlink) {
    root.link_target = read_link_target(path, &root.st);
  }

  if (g_cfg.full_path) {
    root_label = root.path;
  }

  print_entry_line(&root, "", true, true, root_label);

  if (root.is_dir) {
    walk_tree(root.path, 0, "");
  } else {
    g_cfg.file_count = 1;
  }

  printf("\n%lld directories, %lld files\n", g_cfg.dir_count, g_cfg.file_count);

  free(root.name);
  free(root.path);
  free(root.link_target);
  return g_cfg.error_count > 0 ? 1 : 0;
}

int main(int argc, char **argv) {
  const char *path;
  int exit_code;

  g_cfg.use_color = isatty(STDOUT_FILENO);
  path = parse_args(argc, argv);
  exit_code = print_root_and_walk(path);
  free_config();
  return exit_code;
}
