#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pwd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <ApplicationServices/ApplicationServices.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/ps/IOPowerSources.h>
#include <IOKit/ps/IOPSKeys.h>
#include <mach/host_info.h>
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <sys/sysctl.h>
#else
#include <sys/sysinfo.h>
#endif

#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))
#define MAX_SELECTED_FIELDS 32
#define MAX_TEXT_LINES 40

typedef struct {
  char username[64];
  char hostname[64];
  char os[128];
  char host[128];
  char arch[64];
  char kernel[128];
  char uptime[64];
  char shell[64];
  char term[64];
  char resolution[128];
  char cpu[128];
  char cpu_cores[64];
  char gpu[256];
  char load_avg[64];
  char memory[128];
  char swap[128];
  char battery[64];
  char battery_health[64];
  char local_ip[64];
  char disk[128];
  char packages[128];
} SystemInfo;

typedef struct {
  bool use_color;
  const char *c1;
  const char *c2;
  const char *c3;
  const char *reset;
} Colors;

typedef struct {
  bool show_logo;
  bool compact;
  bool json;
  size_t selected_count;
  size_t selected_indices[MAX_SELECTED_FIELDS];
} OutputOptions;

typedef struct {
  const char *name;
  const char *json_key;
  const char *label;
  size_t offset;
  bool default_visible;
} FieldDef;

static const char *RAW_LOGO[] = {
  "                        .8",
  "                      .888",
  "                    .8888'",
  "                   .8888'",
  "                   888'",
  "                   8'",
  "      .88888888888. .88888888888.",
  "   .8888888888888888888888888888888.",
  " .8888888888888888888888888888888888.",
  ".&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&'",
  "&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&'",
  "&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&'",
  "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@: ",
  "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@: ",
  "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@: ",
  "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%.",
  "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%.",
  "`%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%.",
  " `00000000000000000000000000000000000'",
  "  `000000000000000000000000000000000'",
  "   `0000000000000000000000000000000'",
  "     `###########################'",
  "       `#######################'",
  "         `#########''########'",
  "           `\"\"\"\"\"\"'  `\"\"\"\"\"'"
};

static const FieldDef FIELD_DEFS[] = {
  {"user", "user", "User", offsetof(SystemInfo, username), false},
  {"hostname", "hostname", "Hostname", offsetof(SystemInfo, hostname), false},
  {"os", "os", "OS", offsetof(SystemInfo, os), true},
  {"host", "host", "Host", offsetof(SystemInfo, host), true},
  {"arch", "arch", "Arch", offsetof(SystemInfo, arch), true},
  {"kernel", "kernel", "Kernel", offsetof(SystemInfo, kernel), true},
  {"uptime", "uptime", "Uptime", offsetof(SystemInfo, uptime), true},
  {"shell", "shell", "Shell", offsetof(SystemInfo, shell), true},
  {"term", "term", "Term", offsetof(SystemInfo, term), true},
  {"resolution", "resolution", "Resolution", offsetof(SystemInfo, resolution), true},
  {"cpu", "cpu", "CPU", offsetof(SystemInfo, cpu), true},
  {"cores", "cores", "Cores", offsetof(SystemInfo, cpu_cores), true},
  {"gpu", "gpu", "GPU", offsetof(SystemInfo, gpu), true},
  {"load", "load", "Load", offsetof(SystemInfo, load_avg), true},
  {"memory", "memory", "Memory", offsetof(SystemInfo, memory), true},
  {"swap", "swap", "Swap", offsetof(SystemInfo, swap), true},
  {"battery", "battery", "Battery", offsetof(SystemInfo, battery), true},
  {"battery-health", "battery_health", "Battery Health",
   offsetof(SystemInfo, battery_health), true},
  {"local-ip", "local_ip", "Local IP", offsetof(SystemInfo, local_ip), true},
  {"disk", "disk", "Disk", offsetof(SystemInfo, disk), true},
  {"packages", "packages", "Packages", offsetof(SystemInfo, packages), true}
};

static void copy_string(char *dst, size_t dst_size, const char *src) {
  if (dst_size == 0) {
    return;
  }
  if (src == NULL) {
    dst[0] = '\0';
    return;
  }
  snprintf(dst, dst_size, "%s", src);
}

static const char *base_name(const char *path) {
  const char *slash = strrchr(path, '/');
  return slash == NULL ? path : slash + 1;
}

static void trim_in_place(char *value) {
  size_t start = 0;
  size_t end;

  if (value == NULL) {
    return;
  }

  while (value[start] != '\0' && isspace((unsigned char) value[start])) {
    start++;
  }

  end = strlen(value);
  while (end > start && isspace((unsigned char) value[end - 1])) {
    end--;
  }

  if (start > 0) {
    memmove(value, value + start, end - start);
  }
  value[end - start] = '\0';
}

static void append_text(char *out, size_t out_size, const char *text) {
  size_t len;

  if (out_size == 0 || text == NULL || text[0] == '\0') {
    return;
  }

  len = strlen(out);
  if (len >= out_size - 1) {
    return;
  }

  snprintf(out + len, out_size - len, "%s", text);
}

static void append_list_item(char *out, size_t out_size, const char *item) {
  if (item == NULL || item[0] == '\0') {
    return;
  }
  if (out[0] != '\0') {
    append_text(out, out_size, ", ");
  }
  append_text(out, out_size, item);
}

static bool parse_int_after_equals(const char *line, int *out) {
  const char *eq;

  if (line == NULL || out == NULL) {
    return false;
  }

  eq = strchr(line, '=');
  if (eq == NULL) {
    return false;
  }
  eq++;
  while (*eq != '\0' && isspace((unsigned char) *eq)) {
    eq++;
  }

  return sscanf(eq, "%d", out) == 1;
}

static void human_bytes(unsigned long long bytes, char *out, size_t out_size) {
  static const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB"};
  double value = (double) bytes;
  size_t unit = 0;

  while (value >= 1024.0 && unit + 1 < ARRAY_LEN(units)) {
    value /= 1024.0;
    unit++;
  }

  if (unit == 0) {
    snprintf(out, out_size, "%llu %s", bytes, units[unit]);
  } else {
    snprintf(out, out_size, "%.1f %s", value, units[unit]);
  }
}

static void format_uptime(unsigned long long total_seconds, char *out,
                          size_t out_size) {
  unsigned long long days;
  unsigned long long hours;
  unsigned long long mins;

  if (total_seconds == 0) {
    copy_string(out, out_size, "unknown");
    return;
  }

  days = total_seconds / 86400ULL;
  hours = (total_seconds % 86400ULL) / 3600ULL;
  mins = (total_seconds % 3600ULL) / 60ULL;

  if (days > 0) {
    snprintf(out, out_size, "%llud %lluh %llum", days, hours, mins);
  } else if (hours > 0) {
    snprintf(out, out_size, "%lluh %llum", hours, mins);
  } else {
    snprintf(out, out_size, "%llum", mins);
  }
}

static void format_memory_total_label(unsigned long long bytes, char *out,
                                      size_t out_size) {
  double gib = (double) bytes / (1024.0 * 1024.0 * 1024.0);
  snprintf(out, out_size, "%.0f GB", gib);
}

#ifndef __APPLE__
static bool read_first_line(const char *path, char *out, size_t out_size) {
  FILE *fp = fopen(path, "r");

  if (fp == NULL) {
    return false;
  }
  if (fgets(out, (int) out_size, fp) == NULL) {
    fclose(fp);
    return false;
  }

  fclose(fp);
  trim_in_place(out);
  return out[0] != '\0';
}

static bool read_first_match(const char *path, const char *prefix, char *out,
                             size_t out_size) {
  FILE *fp = fopen(path, "r");
  char line[512];

  if (fp == NULL) {
    return false;
  }

  while (fgets(line, sizeof(line), fp) != NULL) {
    if (strncmp(line, prefix, strlen(prefix)) == 0) {
      copy_string(out, out_size, line + strlen(prefix));
      trim_in_place(out);
      fclose(fp);
      return true;
    }
  }

  fclose(fp);
  return false;
}

static bool read_binary_string(const char *path, char *out, size_t out_size) {
  FILE *fp = fopen(path, "rb");
  size_t bytes_read;
  size_t len;

  if (fp == NULL || out_size == 0) {
    if (fp != NULL) {
      fclose(fp);
    }
    return false;
  }

  bytes_read = fread(out, 1, out_size - 1, fp);
  fclose(fp);
  if (bytes_read == 0) {
    out[0] = '\0';
    return false;
  }

  out[bytes_read] = '\0';
  len = bytes_read;
  while (len > 0 &&
         (out[len - 1] == '\0' || isspace((unsigned char) out[len - 1]))) {
    len--;
  }
  out[len] = '\0';
  trim_in_place(out);
  return out[0] != '\0';
}

static bool read_ull_file(const char *path, unsigned long long *out) {
  FILE *fp = fopen(path, "r");

  if (fp == NULL) {
    return false;
  }

  if (fscanf(fp, "%llu", out) == 1) {
    fclose(fp);
    return true;
  }

  fclose(fp);
  return false;
}

static bool run_count_command(const char *cmd, unsigned long long *out) {
  FILE *fp = popen(cmd, "r");

  if (fp == NULL) {
    return false;
  }
  if (fscanf(fp, "%llu", out) == 1) {
    pclose(fp);
    return true;
  }

  pclose(fp);
  return false;
}
#endif

static unsigned long long count_directory_entries(const char *path) {
  DIR *dir = opendir(path);
  struct dirent *entry;
  unsigned long long count = 0;

  if (dir == NULL) {
    return 0;
  }

  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }
    count++;
  }

  closedir(dir);
  return count;
}

static void append_count_item(char *out, size_t out_size, const char *label,
                              unsigned long long count) {
  char item[64];

  if (count == 0) {
    return;
  }

  snprintf(item, sizeof(item), "%llu (%s)", count, label);
  append_list_item(out, out_size, item);
}

static void get_username(char *out, size_t out_size) {
  const char *value = getenv("USER");
  struct passwd *pw;

  if (value != NULL && value[0] != '\0') {
    copy_string(out, out_size, value);
    return;
  }

  pw = getpwuid(getuid());
  if (pw != NULL && pw->pw_name != NULL) {
    copy_string(out, out_size, pw->pw_name);
    return;
  }

  copy_string(out, out_size, "unknown");
}

static void get_hostname_short(char *out, size_t out_size) {
  char buffer[256];
  char *dot;

  if (gethostname(buffer, sizeof(buffer)) != 0) {
    copy_string(out, out_size, "unknown");
    return;
  }

  buffer[sizeof(buffer) - 1] = '\0';
  dot = strchr(buffer, '.');
  if (dot != NULL) {
    *dot = '\0';
  }

  copy_string(out, out_size, buffer);
}

static void get_shell_name(char *out, size_t out_size) {
  const char *shell = getenv("SHELL");

  if (shell == NULL || shell[0] == '\0') {
    copy_string(out, out_size, "unknown");
    return;
  }

  copy_string(out, out_size, base_name(shell));
}

static void get_term_name(char *out, size_t out_size) {
  const char *term_program = getenv("TERM_PROGRAM");
  const char *term = getenv("TERM");

  if (term_program != NULL && term_program[0] != '\0') {
    copy_string(out, out_size, term_program);
    return;
  }
  if (term != NULL && term[0] != '\0') {
    copy_string(out, out_size, term);
    return;
  }

  copy_string(out, out_size, "unknown");
}

static void get_kernel_release(char *out, size_t out_size) {
  struct utsname uts;

  if (uname(&uts) == 0) {
    copy_string(out, out_size, uts.release);
    return;
  }

  copy_string(out, out_size, "unknown");
}

static void get_arch_string(char *out, size_t out_size) {
  struct utsname uts;

  if (uname(&uts) == 0 && uts.machine[0] != '\0') {
    copy_string(out, out_size, uts.machine);
    return;
  }

  copy_string(out, out_size, "unknown");
}

static void get_disk_usage(char *out, size_t out_size) {
  const char *home = getenv("HOME");
  const char *target = home;
  struct statvfs stat_buf;
  unsigned long long total;
  unsigned long long used;
  unsigned long long pct;
  char used_text[32];
  char total_text[32];

  if (target == NULL || target[0] == '\0' || access(target, F_OK) != 0) {
    target = "/";
  }

#ifdef __APPLE__
  if (strchr(target, '\'') == NULL) {
    FILE *fp;
    char cmd[512];
    char line[512];

    snprintf(cmd, sizeof(cmd), "df -kP '%s' 2>/dev/null", target);
    fp = popen(cmd, "r");
    if (fp != NULL) {
      if (fgets(line, sizeof(line), fp) != NULL &&
          fgets(line, sizeof(line), fp) != NULL) {
        unsigned long long total_kib = 0;
        unsigned long long used_kib = 0;

        if (sscanf(line, "%*s %llu %llu", &total_kib, &used_kib) == 2) {
          pclose(fp);
          human_bytes(used_kib * 1024ULL, used_text, sizeof(used_text));
          human_bytes(total_kib * 1024ULL, total_text, sizeof(total_text));
          pct = total_kib > 0 ? (used_kib * 100ULL + total_kib / 2ULL) / total_kib : 0;
          snprintf(out, out_size, "%s / %s (%llu%%)", used_text, total_text, pct);
          return;
        }
      }
      pclose(fp);
    }
  }
#endif

  if (statvfs(target, &stat_buf) != 0 || stat_buf.f_blocks == 0) {
    copy_string(out, out_size, "unknown");
    return;
  }

  total = (unsigned long long) stat_buf.f_frsize * stat_buf.f_blocks;
  used = (unsigned long long) stat_buf.f_frsize *
         (stat_buf.f_blocks - stat_buf.f_bfree);

  human_bytes(used, used_text, sizeof(used_text));
  human_bytes(total, total_text, sizeof(total_text));
  pct = total > 0 ? (used * 100ULL + total / 2ULL) / total : 0;
  snprintf(out, out_size, "%s / %s (%llu%%)", used_text, total_text, pct);
}

static void get_local_ip(char *out, size_t out_size) {
  struct ifaddrs *ifaddr = NULL;
  struct ifaddrs *ifa;

  if (getifaddrs(&ifaddr) != 0) {
    copy_string(out, out_size, "unknown");
    return;
  }

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    void *addr_ptr;
    char address[INET_ADDRSTRLEN];

    if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) {
      continue;
    }
    if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) {
      continue;
    }
    if ((ifa->ifa_flags & IFF_UP) == 0) {
      continue;
    }

    addr_ptr = &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
    if (inet_ntop(AF_INET, addr_ptr, address, sizeof(address)) != NULL) {
      copy_string(out, out_size, address);
      freeifaddrs(ifaddr);
      return;
    }
  }

  freeifaddrs(ifaddr);
  copy_string(out, out_size, "unknown");
}

#ifdef __APPLE__
static bool cfstring_to_cstr(CFStringRef value, char *out, size_t out_size) {
  if (value == NULL || out_size == 0) {
    return false;
  }

  if (CFStringGetCString(value, out, (CFIndex) out_size,
                         kCFStringEncodingUTF8)) {
    return true;
  }

  out[0] = '\0';
  return false;
}

static bool cfvalue_to_string(CFTypeRef value, char *out, size_t out_size) {
  if (value == NULL || out_size == 0) {
    return false;
  }

  if (CFGetTypeID(value) == CFStringGetTypeID()) {
    return cfstring_to_cstr((CFStringRef) value, out, out_size);
  }

  if (CFGetTypeID(value) == CFDataGetTypeID()) {
    CFDataRef data = (CFDataRef) value;
    CFIndex len = CFDataGetLength(data);
    const UInt8 *bytes = CFDataGetBytePtr(data);
    size_t copy_len;

    if (bytes == NULL) {
      out[0] = '\0';
      return false;
    }

    copy_len = (size_t) len;
    while (copy_len > 0 && bytes[copy_len - 1] == '\0') {
      copy_len--;
    }
    if (copy_len >= out_size) {
      copy_len = out_size - 1;
    }

    memcpy(out, bytes, copy_len);
    out[copy_len] = '\0';
    return copy_len > 0;
  }

  out[0] = '\0';
  return false;
}

static bool load_plist_string_value(const char *path, const char *key_name,
                                    char *out, size_t out_size) {
  FILE *fp = NULL;
  unsigned char *buffer = NULL;
  long file_size;
  size_t read_size;
  bool ok = false;
  CFDataRef data = NULL;
  CFPropertyListRef plist = NULL;
  CFStringRef key = NULL;
  CFTypeRef value;

  out[0] = '\0';
  fp = fopen(path, "rb");
  if (fp == NULL) {
    return false;
  }

  if (fseek(fp, 0, SEEK_END) != 0) {
    goto cleanup;
  }
  file_size = ftell(fp);
  if (file_size < 0) {
    goto cleanup;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    goto cleanup;
  }

  buffer = malloc((size_t) file_size);
  if (buffer == NULL) {
    goto cleanup;
  }

  read_size = fread(buffer, 1, (size_t) file_size, fp);
  if (read_size != (size_t) file_size) {
    goto cleanup;
  }

  data = CFDataCreate(kCFAllocatorDefault, buffer, (CFIndex) file_size);
  if (data == NULL) {
    goto cleanup;
  }

  plist = CFPropertyListCreateWithData(kCFAllocatorDefault, data, 0, NULL, NULL);
  if (plist == NULL || CFGetTypeID(plist) != CFDictionaryGetTypeID()) {
    goto cleanup;
  }

  key = CFStringCreateWithCString(kCFAllocatorDefault, key_name,
                                  kCFStringEncodingUTF8);
  if (key == NULL) {
    goto cleanup;
  }

  value = CFDictionaryGetValue((CFDictionaryRef) plist, key);
  if (value == NULL) {
    goto cleanup;
  }

  ok = cfvalue_to_string(value, out, out_size);

cleanup:
  if (key != NULL) {
    CFRelease(key);
  }
  if (plist != NULL) {
    CFRelease(plist);
  }
  if (data != NULL) {
    CFRelease(data);
  }
  free(buffer);
  if (fp != NULL) {
    fclose(fp);
  }
  return ok;
}

static bool sysctl_string(const char *name, char *out, size_t out_size) {
  size_t len = out_size;

  if (out_size == 0) {
    return false;
  }

  out[0] = '\0';
  if (sysctlbyname(name, out, &len, NULL, 0) != 0) {
    out[0] = '\0';
    return false;
  }
  if (len == 0) {
    out[0] = '\0';
    return false;
  }

  out[out_size - 1] = '\0';
  return out[0] != '\0';
}

static bool sysctl_u64(const char *name, uint64_t *out) {
  size_t len = sizeof(*out);

  if (sysctlbyname(name, out, &len, NULL, 0) != 0 || len != sizeof(*out)) {
    return false;
  }

  return true;
}

static bool sysctl_u32(const char *name, uint32_t *out) {
  size_t len = sizeof(*out);

  if (sysctlbyname(name, out, &len, NULL, 0) != 0 || len != sizeof(*out)) {
    return false;
  }

  return true;
}

static bool io_registry_copy_string(io_registry_entry_t service,
                                    const char *key_name, char *out,
                                    size_t out_size) {
  CFStringRef key = CFStringCreateWithCString(kCFAllocatorDefault, key_name,
                                              kCFStringEncodingUTF8);
  CFTypeRef value;
  bool ok;

  if (key == NULL) {
    return false;
  }

  value = IORegistryEntryCreateCFProperty(service, key, kCFAllocatorDefault, 0);
  CFRelease(key);
  if (value == NULL) {
    return false;
  }

  ok = cfvalue_to_string(value, out, out_size);
  CFRelease(value);
  return ok;
}

static bool io_registry_copy_int(io_registry_entry_t service, const char *key_name,
                                 int *out) {
  CFStringRef key = CFStringCreateWithCString(kCFAllocatorDefault, key_name,
                                              kCFStringEncodingUTF8);
  CFTypeRef value;
  bool ok = false;

  if (key == NULL) {
    return false;
  }

  value = IORegistryEntryCreateCFProperty(service, key, kCFAllocatorDefault, 0);
  CFRelease(key);
  if (value == NULL) {
    return false;
  }

  if (CFGetTypeID(value) == CFNumberGetTypeID()) {
    ok = CFNumberGetValue((CFNumberRef) value, kCFNumberIntType, out);
  }

  CFRelease(value);
  return ok;
}

static void get_os_name(char *out, size_t out_size) {
  char name[64];
  char version[64];

  if (load_plist_string_value("/System/Library/CoreServices/SystemVersion.plist",
                              "ProductName", name, sizeof(name)) &&
      load_plist_string_value("/System/Library/CoreServices/SystemVersion.plist",
                              "ProductVersion", version, sizeof(version))) {
    snprintf(out, out_size, "%s %s", name, version);
    return;
  }

  if (sysctl_string("kern.osproductversion", version, sizeof(version))) {
    snprintf(out, out_size, "macOS %s", version);
    return;
  }

  copy_string(out, out_size, "macOS");
}

static void get_uptime_string(char *out, size_t out_size) {
  FILE *fp = popen("who -b 2>/dev/null", "r");

  if (fp != NULL) {
    char buffer[256];

    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
      char month[8];
      int day = 0;
      int hour = 0;
      int minute = 0;

      if (sscanf(buffer, "%*s %*s %7s %d %d:%d",
                 month, &day, &hour, &minute) == 4) {
        struct tm tm_boot;
        struct tm tm_now;
        char stamp[64];
        time_t now = time(NULL);
        time_t boot;

        localtime_r(&now, &tm_now);
        memset(&tm_boot, 0, sizeof(tm_boot));
        tm_boot.tm_year = tm_now.tm_year;
        tm_boot.tm_isdst = -1;

        snprintf(stamp, sizeof(stamp), "%s %d %02d:%02d",
                 month, day, hour, minute);
        if (strptime(stamp, "%b %d %H:%M", &tm_boot) != NULL) {
          boot = mktime(&tm_boot);
          if (boot > now) {
            tm_boot.tm_year--;
            boot = mktime(&tm_boot);
          }
          if (boot > 0 && now > boot) {
            pclose(fp);
            format_uptime((unsigned long long) (now - boot), out, out_size);
            return;
          }
        }
      }
    }
    pclose(fp);
  }

  copy_string(out, out_size, "unknown");
}

static void get_cpu_cores_string(char *out, size_t out_size) {
  uint32_t physical = 0;
  uint32_t logical = 0;

  sysctl_u32("hw.physicalcpu", &physical);
  sysctl_u32("hw.logicalcpu", &logical);

  if (physical > 0 && logical > 0) {
    snprintf(out, out_size, "%u physical / %u logical", physical, logical);
    return;
  }
  if (logical > 0) {
    snprintf(out, out_size, "%u logical", logical);
    return;
  }

  copy_string(out, out_size, "unknown");
}

static void get_load_string(char *out, size_t out_size) {
  double samples[3];

  if (getloadavg(samples, 3) == 3) {
    snprintf(out, out_size, "%.2f %.2f %.2f",
             samples[0], samples[1], samples[2]);
    return;
  }

  copy_string(out, out_size, "unknown");
}

static void get_host_model(char *out, size_t out_size) {
  io_registry_entry_t service;

  if (sysctl_string("hw.model", out, out_size)) {
    return;
  }

  service = IOServiceGetMatchingService(kIOMainPortDefault,
                                        IOServiceMatching("IOPlatformExpertDevice"));
  if (service != IO_OBJECT_NULL) {
    if (io_registry_copy_string(service, "model", out, out_size)) {
      IOObjectRelease(service);
      return;
    }
    IOObjectRelease(service);
  }

  copy_string(out, out_size, "unknown");
}

static void get_apple_gpu_info(char *gpu_model, size_t gpu_model_size,
                               int *gpu_cores) {
  io_iterator_t iter = IO_OBJECT_NULL;
  CFMutableDictionaryRef match = NULL;
  kern_return_t kr;

  gpu_model[0] = '\0';
  *gpu_cores = 0;

  match = IOServiceMatching("IOAccelerator");
  if (match == NULL) {
    return;
  }

  kr = IOServiceGetMatchingServices(kIOMainPortDefault, match, &iter);
  if (kr != KERN_SUCCESS) {
    return;
  }

  for (;;) {
    io_registry_entry_t service = IOIteratorNext(iter);
    char model[128];
    int cores = 0;

    if (service == IO_OBJECT_NULL) {
      break;
    }

    model[0] = '\0';
    if (io_registry_copy_string(service, "model", model, sizeof(model))) {
      io_registry_copy_int(service, "gpu-core-count", &cores);
      copy_string(gpu_model, gpu_model_size, model);
      *gpu_cores = cores;
      IOObjectRelease(service);
      break;
    }

    IOObjectRelease(service);
  }

  IOObjectRelease(iter);
}

static void get_cpu_name(char *out, size_t out_size) {
  char gpu_model[128];
  int gpu_cores = 0;

  if (sysctl_string("machdep.cpu.brand_string", out, out_size)) {
    return;
  }

  get_apple_gpu_info(gpu_model, sizeof(gpu_model), &gpu_cores);
  if (gpu_model[0] != '\0') {
    copy_string(out, out_size, gpu_model);
    return;
  }

  copy_string(out, out_size, "unknown");
}

static void get_gpu_name(char *out, size_t out_size) {
  char gpu_model[128];
  int gpu_cores = 0;

  get_apple_gpu_info(gpu_model, sizeof(gpu_model), &gpu_cores);
  if (gpu_model[0] == '\0') {
    copy_string(out, out_size, "unknown");
    return;
  }

  if (gpu_cores > 0) {
    snprintf(out, out_size, "%s (%d cores)", gpu_model, gpu_cores);
    return;
  }

  copy_string(out, out_size, gpu_model);
}

static void append_resolution_mode(char *out, size_t out_size,
                                   size_t width, size_t height) {
  char item[32];

  if (width == 0 || height == 0) {
    return;
  }

  snprintf(item, sizeof(item), "%zux%zu", width, height);
  append_list_item(out, out_size, item);
}

static void append_resolution_line(char *out, size_t out_size, const char *line) {
  unsigned int width = 0;
  unsigned int height = 0;

  if (sscanf(line, "Resolution: %u x %u", &width, &height) == 2) {
    append_resolution_mode(out, out_size, width, height);
  }
}

static void get_resolution_string(char *out, size_t out_size) {
  CGDirectDisplayID displays[16];
  uint32_t count = 0;
  size_t i;

  out[0] = '\0';
  if (CGGetOnlineDisplayList((uint32_t) ARRAY_LEN(displays), displays, &count) ==
      kCGErrorSuccess) {
    if (count > ARRAY_LEN(displays)) {
      count = (uint32_t) ARRAY_LEN(displays);
    }
    for (i = 0; i < count; i++) {
      size_t width = (size_t) CGDisplayPixelsWide(displays[i]);
      size_t height = (size_t) CGDisplayPixelsHigh(displays[i]);
      append_resolution_mode(out, out_size, width, height);
    }
  }
  if (out[0] != '\0') {
    return;
  }

  {
    FILE *fp = popen("system_profiler SPDisplaysDataType 2>/dev/null", "r");
    if (fp != NULL) {
      char line[256];

      while (fgets(line, sizeof(line), fp) != NULL) {
        trim_in_place(line);
        append_resolution_line(out, out_size, line);
      }
      pclose(fp);
    }
  }

  if (out[0] == '\0') {
    copy_string(out, out_size, "unknown");
  }
}

static void get_memory_string(char *out, size_t out_size) {
  uint64_t total_bytes = 0;
  char used_text[32];
  char total_text[32];

  if (!sysctl_u64("hw.memsize", &total_bytes)) {
    copy_string(out, out_size, "unknown");
    return;
  }

  {
    FILE *fp = popen("vm_stat 2>/dev/null", "r");
    if (fp != NULL) {
      char line[256];
      unsigned long long page_size = 0;
      unsigned long long active = 0;
      unsigned long long wired = 0;
      unsigned long long compressed = 0;

      while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "Mach Virtual Memory Statistics: (page size of %llu bytes)",
                   &page_size) == 1) {
          continue;
        }
        if (sscanf(line, "Pages active: %llu.", &active) == 1) {
          continue;
        }
        if (sscanf(line, "Pages wired down: %llu.", &wired) == 1) {
          continue;
        }
        if (sscanf(line, "Pages occupied by compressor: %llu.", &compressed) == 1) {
          continue;
        }
      }
      pclose(fp);

      if (page_size > 0) {
        unsigned long long used_bytes =
          (active + wired + compressed) * page_size;
        human_bytes(used_bytes, used_text, sizeof(used_text));
        format_memory_total_label(total_bytes, total_text, sizeof(total_text));
        snprintf(out, out_size, "%s / %s", used_text, total_text);
        return;
      }
    }
  }

  {
    mach_port_t host_port = mach_host_self();
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    vm_statistics64_data_t vm_stat;
    vm_size_t page_size = 0;
    unsigned long long used_bytes;

    if (host_page_size(host_port, &page_size) != KERN_SUCCESS) {
      copy_string(out, out_size, "unknown");
      return;
    }

    if (host_statistics64(host_port, HOST_VM_INFO64, (host_info64_t) &vm_stat,
                          &count) != KERN_SUCCESS) {
      copy_string(out, out_size, "unknown");
      return;
    }

    used_bytes = ((unsigned long long) vm_stat.active_count +
                  (unsigned long long) vm_stat.wire_count +
                  (unsigned long long) vm_stat.compressor_page_count) *
                 (unsigned long long) page_size;

    human_bytes(used_bytes, used_text, sizeof(used_text));
    format_memory_total_label(total_bytes, total_text, sizeof(total_text));
    snprintf(out, out_size, "%s / %s", used_text, total_text);
  }
}

static void get_swap_string(char *out, size_t out_size) {
  struct xsw_usage usage;
  size_t len = sizeof(usage);
  char used_text[32];
  char total_text[32];

  if (sysctlbyname("vm.swapusage", &usage, &len, NULL, 0) != 0 ||
      len != sizeof(usage) || usage.xsu_total == 0) {
    copy_string(out, out_size, "n/a");
    return;
  }

  human_bytes(usage.xsu_used, used_text, sizeof(used_text));
  human_bytes(usage.xsu_total, total_text, sizeof(total_text));
  snprintf(out, out_size, "%s / %s", used_text, total_text);
}

static void get_battery_string(char *out, size_t out_size) {
  CFTypeRef info = IOPSCopyPowerSourcesInfo();
  CFArrayRef list = NULL;
  CFDictionaryRef desc = NULL;

  if (info == NULL) {
    out[0] = '\0';
    return;
  }

  list = IOPSCopyPowerSourcesList(info);
  if (list == NULL || CFArrayGetCount(list) == 0) {
    if (list != NULL) {
      CFRelease(list);
    }
    CFRelease(info);
    out[0] = '\0';
    return;
  }

  desc = IOPSGetPowerSourceDescription(info, CFArrayGetValueAtIndex(list, 0));
  if (desc != NULL) {
    CFNumberRef current_ref;
    CFNumberRef max_ref;
    CFBooleanRef charging_ref;
    CFStringRef state_ref;
    int current = 0;
    int max = 0;
    bool is_charging = false;
    char state[32];
    long pct = 0;

    current_ref = CFDictionaryGetValue(desc, CFSTR(kIOPSCurrentCapacityKey));
    max_ref = CFDictionaryGetValue(desc, CFSTR(kIOPSMaxCapacityKey));
    charging_ref = CFDictionaryGetValue(desc, CFSTR(kIOPSIsChargingKey));
    state_ref = CFDictionaryGetValue(desc, CFSTR(kIOPSPowerSourceStateKey));

    if (current_ref != NULL) {
      CFNumberGetValue(current_ref, kCFNumberIntType, &current);
    }
    if (max_ref != NULL) {
      CFNumberGetValue(max_ref, kCFNumberIntType, &max);
    }
    if (charging_ref != NULL) {
      is_charging = CFBooleanGetValue(charging_ref);
    }

    if (max > 0) {
      pct = (long) ((current * 100 + max / 2) / max);
    }

    if (is_charging) {
      copy_string(state, sizeof(state), "charging");
    } else if (state_ref != NULL &&
               CFStringCompare(state_ref, CFSTR(kIOPSACPowerValue), 0) ==
                 kCFCompareEqualTo &&
               current >= max) {
      copy_string(state, sizeof(state), "charged");
    } else {
      copy_string(state, sizeof(state), "discharging");
    }

    if (max > 0) {
      snprintf(out, out_size, "%ld%% (%s)", pct, state);
    } else {
      out[0] = '\0';
    }
  } else {
    out[0] = '\0';
  }

  CFRelease(list);
  CFRelease(info);
}

static void get_battery_health_string(char *out, size_t out_size) {
  int design_capacity = 0;
  int max_capacity = 0;
  long pct;
  FILE *fp = popen("ioreg -rc AppleSmartBattery 2>/dev/null", "r");

  if (fp != NULL) {
    char line[256];

    while (fgets(line, sizeof(line), fp) != NULL) {
      if (strstr(line, "\"DesignCapacity\"") != NULL &&
          parse_int_after_equals(line, &design_capacity)) {
        continue;
      }
      if (strstr(line, "\"NominalChargeCapacity\"") != NULL &&
          parse_int_after_equals(line, &max_capacity)) {
        continue;
      }
      if (max_capacity == 0 &&
          strstr(line, "\"AppleRawMaxCapacity\"") != NULL &&
          parse_int_after_equals(line, &max_capacity)) {
        continue;
      }
    }
    pclose(fp);
  }

  if (design_capacity <= 0 || max_capacity <= 0) {
    out[0] = '\0';
    return;
  }

  pct = (long) ((max_capacity * 100L + design_capacity / 2L) / design_capacity);
  snprintf(out, out_size, "%ld%%", pct);
}

static void get_packages_string(char *out, size_t out_size) {
  unsigned long long brew_count = 0;
  unsigned long long cask_count = 0;
  unsigned long long ports_count = 0;

  out[0] = '\0';

  brew_count = count_directory_entries("/opt/homebrew/Cellar");
  if (brew_count == 0) {
    brew_count = count_directory_entries("/usr/local/Cellar");
  }

  cask_count = count_directory_entries("/opt/homebrew/Caskroom");
  if (cask_count == 0) {
    cask_count = count_directory_entries("/usr/local/Caskroom");
  }

  ports_count = count_directory_entries("/opt/local/var/macports/software");

  append_count_item(out, out_size, "brew", brew_count);
  append_count_item(out, out_size, "cask", cask_count);
  append_count_item(out, out_size, "ports", ports_count);

  if (out[0] == '\0') {
    copy_string(out, out_size, "n/a");
  }
}
#else
static unsigned long long count_matching_lines(const char *path,
                                               const char *prefix) {
  FILE *fp = fopen(path, "r");
  char line[512];
  unsigned long long count = 0;

  if (fp == NULL) {
    return 0;
  }

  while (fgets(line, sizeof(line), fp) != NULL) {
    if (strncmp(line, prefix, strlen(prefix)) == 0) {
      count++;
    }
  }

  fclose(fp);
  return count;
}

static bool linux_find_battery_dir(char *out, size_t out_size) {
  DIR *dir = opendir("/sys/class/power_supply");
  struct dirent *entry;

  if (dir == NULL) {
    return false;
  }

  while ((entry = readdir(dir)) != NULL) {
    char type_path[512];
    char type[64];

    if (entry->d_name[0] == '.') {
      continue;
    }

    snprintf(type_path, sizeof(type_path), "/sys/class/power_supply/%s/type",
             entry->d_name);
    if (!read_first_line(type_path, type, sizeof(type))) {
      continue;
    }
    if (strcmp(type, "Battery") == 0) {
      snprintf(out, out_size, "/sys/class/power_supply/%s", entry->d_name);
      closedir(dir);
      return true;
    }
  }

  closedir(dir);
  return false;
}

static void get_os_name(char *out, size_t out_size) {
  FILE *fp = fopen("/etc/os-release", "r");
  char line[512];

  if (fp == NULL) {
    struct utsname uts;
    if (uname(&uts) == 0) {
      copy_string(out, out_size, uts.sysname);
    } else {
      copy_string(out, out_size, "Linux");
    }
    return;
  }

  while (fgets(line, sizeof(line), fp) != NULL) {
    if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
      char *value = line + 12;
      trim_in_place(value);
      if (value[0] == '"' || value[0] == '\'') {
        size_t len = strlen(value);
        memmove(value, value + 1, len);
        len = strlen(value);
        if (len > 0 && (value[len - 1] == '"' || value[len - 1] == '\'')) {
          value[len - 1] = '\0';
        }
      }
      copy_string(out, out_size, value);
      fclose(fp);
      return;
    }
  }

  fclose(fp);
  copy_string(out, out_size, "Linux");
}

static void get_uptime_string(char *out, size_t out_size) {
  struct sysinfo info;

  if (sysinfo(&info) == 0) {
    format_uptime((unsigned long long) info.uptime, out, out_size);
    return;
  }

  copy_string(out, out_size, "unknown");
}

static bool linux_add_core_pair(int physical_id, int core_id, int *physical_ids,
                                int *core_ids, size_t *count,
                                size_t capacity) {
  size_t i;

  if (physical_id < 0 || core_id < 0 || *count >= capacity) {
    return false;
  }

  for (i = 0; i < *count; i++) {
    if (physical_ids[i] == physical_id && core_ids[i] == core_id) {
      return true;
    }
  }

  physical_ids[*count] = physical_id;
  core_ids[*count] = core_id;
  (*count)++;
  return true;
}

static bool linux_physical_core_count(unsigned int *out) {
  FILE *fp = fopen("/proc/cpuinfo", "r");
  char line[256];
  int physical_ids[512];
  int core_ids[512];
  size_t pair_count = 0;
  int current_physical = -1;
  int current_core = -1;
  unsigned int cpu_cores = 0;

  if (fp == NULL) {
    return false;
  }

  while (fgets(line, sizeof(line), fp) != NULL) {
    unsigned int parsed_cores = 0;

    if (sscanf(line, "physical id : %d", &current_physical) == 1) {
      continue;
    }
    if (sscanf(line, "core id : %d", &current_core) == 1) {
      continue;
    }
    if (cpu_cores == 0 &&
        sscanf(line, "cpu cores : %u", &parsed_cores) == 1 &&
        parsed_cores > 0) {
      cpu_cores = parsed_cores;
      continue;
    }
    if (line[0] == '\n') {
      linux_add_core_pair(current_physical, current_core, physical_ids, core_ids,
                          &pair_count, ARRAY_LEN(physical_ids));
      current_physical = -1;
      current_core = -1;
    }
  }

  fclose(fp);
  linux_add_core_pair(current_physical, current_core, physical_ids, core_ids,
                      &pair_count, ARRAY_LEN(physical_ids));

  if (pair_count > 0) {
    *out = (unsigned int) pair_count;
    return true;
  }
  if (cpu_cores > 0) {
    *out = cpu_cores;
    return true;
  }

  return false;
}

static void get_cpu_cores_string(char *out, size_t out_size) {
  long logical = sysconf(_SC_NPROCESSORS_ONLN);
  unsigned int physical = 0;

  if (linux_physical_core_count(&physical) && logical > 0) {
    snprintf(out, out_size, "%u physical / %ld logical", physical, logical);
    return;
  }
  if (logical > 0) {
    snprintf(out, out_size, "%ld logical", logical);
    return;
  }

  copy_string(out, out_size, "unknown");
}

static void get_load_string(char *out, size_t out_size) {
  FILE *fp = fopen("/proc/loadavg", "r");
  double one = 0.0;
  double five = 0.0;
  double fifteen = 0.0;

  if (fp == NULL) {
    copy_string(out, out_size, "unknown");
    return;
  }

  if (fscanf(fp, "%lf %lf %lf", &one, &five, &fifteen) == 3) {
    fclose(fp);
    snprintf(out, out_size, "%.2f %.2f %.2f", one, five, fifteen);
    return;
  }

  fclose(fp);
  copy_string(out, out_size, "unknown");
}

static void get_host_model(char *out, size_t out_size) {
  FILE *fp = fopen("/sys/devices/virtual/dmi/id/product_name", "r");
  char line[256];
  struct utsname uts;

  if (fp != NULL) {
    if (fgets(line, sizeof(line), fp) != NULL) {
      trim_in_place(line);
      copy_string(out, out_size, line);
      fclose(fp);
      return;
    }
    fclose(fp);
  }

  if (uname(&uts) == 0) {
    copy_string(out, out_size, uts.machine);
    return;
  }

  copy_string(out, out_size, "unknown");
}

static void get_cpu_name(char *out, size_t out_size) {
  if (read_first_match("/proc/cpuinfo", "model name\t: ", out, out_size)) {
    return;
  }
  if (read_first_match("/proc/cpuinfo", "Hardware\t: ", out, out_size)) {
    return;
  }
  if (read_first_match("/proc/cpuinfo", "Processor\t: ", out, out_size)) {
    return;
  }
  if (read_first_match("/proc/cpuinfo", "cpu model\t\t: ", out, out_size)) {
    return;
  }
  if (read_binary_string("/sys/firmware/devicetree/base/model", out, out_size)) {
    return;
  }
  if (read_binary_string("/proc/device-tree/model", out, out_size)) {
    return;
  }

  copy_string(out, out_size, "unknown");
}

static bool linux_gpu_from_lspci(char *out, size_t out_size) {
  FILE *fp = popen("lspci -nn 2>/dev/null", "r");
  char line[512];

  if (fp == NULL) {
    return false;
  }

  out[0] = '\0';
  while (fgets(line, sizeof(line), fp) != NULL) {
    char *desc;
    char *rev;
    char item[256];

    if (strstr(line, "VGA compatible controller") == NULL &&
        strstr(line, "3D controller") == NULL &&
        strstr(line, "Display controller") == NULL) {
      continue;
    }

    desc = strstr(line, "]: ");
    if (desc != NULL) {
      desc += 3;
    } else {
      desc = strstr(line, ": ");
      if (desc != NULL) {
        desc += 2;
      }
    }
    if (desc == NULL || desc[0] == '\0') {
      continue;
    }

    copy_string(item, sizeof(item), desc);
    trim_in_place(item);
    rev = strstr(item, " (rev ");
    if (rev != NULL) {
      *rev = '\0';
    }
    append_list_item(out, out_size, item);
  }

  pclose(fp);
  return out[0] != '\0';
}

static const char *linux_pci_vendor_name(unsigned int vendor_id) {
  switch (vendor_id) {
    case 0x1002:
      return "AMD";
    case 0x10de:
      return "NVIDIA";
    case 0x8086:
      return "Intel";
    case 0x1af4:
      return "Virtio";
    default:
      return "PCI";
  }
}

static void get_gpu_name(char *out, size_t out_size) {
  char vendor_text[32];
  char device_text[32];
  unsigned int vendor_id = 0;
  unsigned int device_id = 0;

  if (linux_gpu_from_lspci(out, out_size)) {
    return;
  }
  if (read_first_line("/sys/class/drm/card0/device/vendor",
                      vendor_text, sizeof(vendor_text)) &&
      read_first_line("/sys/class/drm/card0/device/device",
                      device_text, sizeof(device_text)) &&
      sscanf(vendor_text, "0x%x", &vendor_id) == 1 &&
      sscanf(device_text, "0x%x", &device_id) == 1) {
    snprintf(out, out_size, "%s (0x%04x)", linux_pci_vendor_name(vendor_id),
             device_id);
    return;
  }

  copy_string(out, out_size, "unknown");
}

static void append_linux_mode(char *out, size_t out_size, const char *mode) {
  char item[64];

  if (mode == NULL || mode[0] == '\0') {
    return;
  }

  copy_string(item, sizeof(item), mode);
  trim_in_place(item);
  append_list_item(out, out_size, item);
}

static void get_resolution_string(char *out, size_t out_size) {
  DIR *dir = opendir("/sys/class/drm");
  struct dirent *entry;

  out[0] = '\0';
  if (dir == NULL) {
    copy_string(out, out_size, "unknown");
    return;
  }

  while ((entry = readdir(dir)) != NULL) {
    char status_path[512];
    char modes_path[512];
    char status[32];
    char mode[64];

    if (strncmp(entry->d_name, "card", 4) != 0 || strchr(entry->d_name, '-') == NULL) {
      continue;
    }

    snprintf(status_path, sizeof(status_path), "/sys/class/drm/%s/status",
             entry->d_name);
    if (!read_first_line(status_path, status, sizeof(status)) ||
        strcmp(status, "connected") != 0) {
      continue;
    }

    snprintf(modes_path, sizeof(modes_path), "/sys/class/drm/%s/modes",
             entry->d_name);
    if (read_first_line(modes_path, mode, sizeof(mode))) {
      append_linux_mode(out, out_size, mode);
    }
  }

  closedir(dir);
  if (out[0] == '\0') {
    copy_string(out, out_size, "unknown");
  }
}

static void get_memory_string(char *out, size_t out_size) {
  FILE *fp = fopen("/proc/meminfo", "r");
  char line[256];
  unsigned long long total_kib = 0;
  unsigned long long available_kib = 0;
  char used_text[32];
  char total_text[32];

  if (fp == NULL) {
    copy_string(out, out_size, "unknown");
    return;
  }

  while (fgets(line, sizeof(line), fp) != NULL) {
    if (sscanf(line, "MemTotal: %llu kB", &total_kib) == 1) {
      continue;
    }
    if (sscanf(line, "MemAvailable: %llu kB", &available_kib) == 1) {
      continue;
    }
  }
  fclose(fp);

  if (total_kib == 0) {
    copy_string(out, out_size, "unknown");
    return;
  }

  human_bytes((total_kib - available_kib) * 1024ULL, used_text, sizeof(used_text));
  human_bytes(total_kib * 1024ULL, total_text, sizeof(total_text));
  snprintf(out, out_size, "%s / %s", used_text, total_text);
}

static void get_swap_string(char *out, size_t out_size) {
  FILE *fp = fopen("/proc/meminfo", "r");
  char line[256];
  unsigned long long total_kib = 0;
  unsigned long long free_kib = 0;
  char used_text[32];
  char total_text[32];

  if (fp == NULL) {
    copy_string(out, out_size, "unknown");
    return;
  }

  while (fgets(line, sizeof(line), fp) != NULL) {
    if (sscanf(line, "SwapTotal: %llu kB", &total_kib) == 1) {
      continue;
    }
    if (sscanf(line, "SwapFree: %llu kB", &free_kib) == 1) {
      continue;
    }
  }
  fclose(fp);

  if (total_kib == 0) {
    copy_string(out, out_size, "n/a");
    return;
  }

  human_bytes((total_kib - free_kib) * 1024ULL, used_text, sizeof(used_text));
  human_bytes(total_kib * 1024ULL, total_text, sizeof(total_text));
  snprintf(out, out_size, "%s / %s", used_text, total_text);
}

static void get_battery_string(char *out, size_t out_size) {
  char battery_dir[512];
  char capacity_path[512];
  char status_path[512];
  char capacity[32];
  char status[32];
  char *p;

  if (!linux_find_battery_dir(battery_dir, sizeof(battery_dir))) {
    out[0] = '\0';
    return;
  }

  snprintf(capacity_path, sizeof(capacity_path), "%s/capacity", battery_dir);
  snprintf(status_path, sizeof(status_path), "%s/status", battery_dir);
  if (!read_first_line(capacity_path, capacity, sizeof(capacity)) ||
      !read_first_line(status_path, status, sizeof(status))) {
    copy_string(out, out_size, "unknown");
    return;
  }

  for (p = status; *p != '\0'; p++) {
    *p = (char) tolower((unsigned char) *p);
  }
  snprintf(out, out_size, "%s%% (%s)", capacity, status);
}

static void get_battery_health_string(char *out, size_t out_size) {
  char battery_dir[512];
  char full_path[512];
  char design_path[512];
  unsigned long long full = 0;
  unsigned long long design = 0;
  unsigned long long pct;

  if (!linux_find_battery_dir(battery_dir, sizeof(battery_dir))) {
    out[0] = '\0';
    return;
  }

  snprintf(full_path, sizeof(full_path), "%s/energy_full", battery_dir);
  snprintf(design_path, sizeof(design_path), "%s/energy_full_design", battery_dir);
  if (!read_ull_file(full_path, &full) || !read_ull_file(design_path, &design)) {
    snprintf(full_path, sizeof(full_path), "%s/charge_full", battery_dir);
    snprintf(design_path, sizeof(design_path), "%s/charge_full_design", battery_dir);
    if (!read_ull_file(full_path, &full) || !read_ull_file(design_path, &design)) {
      out[0] = '\0';
      return;
    }
  }

  if (full == 0 || design == 0) {
    out[0] = '\0';
    return;
  }

  pct = (full * 100ULL + design / 2ULL) / design;
  snprintf(out, out_size, "%llu%%", pct);
}

static void get_packages_string(char *out, size_t out_size) {
  unsigned long long dpkg_count = 0;
  unsigned long long pacman_count = 0;
  unsigned long long apk_count = 0;
  unsigned long long rpm_count = 0;
  unsigned long long xbps_count = 0;

  out[0] = '\0';

  dpkg_count = count_matching_lines("/var/lib/dpkg/status",
                                    "Status: install ok installed");
  pacman_count = count_directory_entries("/var/lib/pacman/local");
  apk_count = count_matching_lines("/lib/apk/db/installed", "P:");
  run_count_command("rpm -qa 2>/dev/null | wc -l", &rpm_count);
  run_count_command("xbps-query -l 2>/dev/null | wc -l", &xbps_count);

  append_count_item(out, out_size, "dpkg", dpkg_count);
  append_count_item(out, out_size, "pacman", pacman_count);
  append_count_item(out, out_size, "apk", apk_count);
  append_count_item(out, out_size, "rpm", rpm_count);
  append_count_item(out, out_size, "xbps", xbps_count);

  if (out[0] == '\0') {
    copy_string(out, out_size, "n/a");
  }
}
#endif

static void fill_system_info(SystemInfo *info) {
  get_username(info->username, sizeof(info->username));
  get_hostname_short(info->hostname, sizeof(info->hostname));
  get_shell_name(info->shell, sizeof(info->shell));
  get_term_name(info->term, sizeof(info->term));
  get_arch_string(info->arch, sizeof(info->arch));
  get_kernel_release(info->kernel, sizeof(info->kernel));
  get_disk_usage(info->disk, sizeof(info->disk));
  get_local_ip(info->local_ip, sizeof(info->local_ip));

  get_os_name(info->os, sizeof(info->os));
  get_uptime_string(info->uptime, sizeof(info->uptime));
  get_host_model(info->host, sizeof(info->host));
  get_resolution_string(info->resolution, sizeof(info->resolution));
  get_cpu_name(info->cpu, sizeof(info->cpu));
  get_cpu_cores_string(info->cpu_cores, sizeof(info->cpu_cores));
  get_gpu_name(info->gpu, sizeof(info->gpu));
  get_load_string(info->load_avg, sizeof(info->load_avg));
  get_memory_string(info->memory, sizeof(info->memory));
  get_swap_string(info->swap, sizeof(info->swap));
  get_battery_string(info->battery, sizeof(info->battery));
  get_battery_health_string(info->battery_health, sizeof(info->battery_health));
  get_packages_string(info->packages, sizeof(info->packages));

  if (info->host[0] == '\0') {
    copy_string(info->host, sizeof(info->host), "unknown");
  }
  if (info->resolution[0] == '\0') {
    copy_string(info->resolution, sizeof(info->resolution), "unknown");
  }
  if (info->gpu[0] == '\0') {
    copy_string(info->gpu, sizeof(info->gpu), "unknown");
  }
  if (info->battery[0] == '\0') {
    copy_string(info->battery, sizeof(info->battery), "n/a");
  }
  if (info->battery_health[0] == '\0') {
    copy_string(info->battery_health, sizeof(info->battery_health), "n/a");
  }
  if (info->local_ip[0] == '\0') {
    copy_string(info->local_ip, sizeof(info->local_ip), "unknown");
  }
  if (info->packages[0] == '\0') {
    copy_string(info->packages, sizeof(info->packages), "n/a");
  }
}

static const char *field_value(const SystemInfo *info, size_t index) {
  return (const char *) ((const char *) info + FIELD_DEFS[index].offset);
}

static int normalized_char(int ch) {
  if (isalnum((unsigned char) ch)) {
    return tolower((unsigned char) ch);
  }
  return 0;
}

static bool normalized_name_equal(const char *a, const char *b) {
  size_t ia = 0;
  size_t ib = 0;

  for (;;) {
    while (a[ia] != '\0' && normalized_char((unsigned char) a[ia]) == 0) {
      ia++;
    }
    while (b[ib] != '\0' && normalized_char((unsigned char) b[ib]) == 0) {
      ib++;
    }

    if (a[ia] == '\0' || b[ib] == '\0') {
      break;
    }
    if (normalized_char((unsigned char) a[ia]) !=
        normalized_char((unsigned char) b[ib])) {
      return false;
    }

    ia++;
    ib++;
  }

  while (a[ia] != '\0' && normalized_char((unsigned char) a[ia]) == 0) {
    ia++;
  }
  while (b[ib] != '\0' && normalized_char((unsigned char) b[ib]) == 0) {
    ib++;
  }

  return a[ia] == '\0' && b[ib] == '\0';
}

static int find_field_index(const char *name) {
  size_t i;

  for (i = 0; i < ARRAY_LEN(FIELD_DEFS); i++) {
    if (normalized_name_equal(name, FIELD_DEFS[i].name) ||
        normalized_name_equal(name, FIELD_DEFS[i].json_key) ||
        normalized_name_equal(name, FIELD_DEFS[i].label)) {
      return (int) i;
    }
  }

  return -1;
}

static bool add_selected_field(OutputOptions *options, size_t index) {
  size_t i;

  for (i = 0; i < options->selected_count; i++) {
    if (options->selected_indices[i] == index) {
      return true;
    }
  }
  if (options->selected_count >= ARRAY_LEN(options->selected_indices)) {
    return false;
  }

  options->selected_indices[options->selected_count++] = index;
  return true;
}

static bool add_field_argument(OutputOptions *options, const char *arg,
                               char *error, size_t error_size) {
  char buffer[256];
  char *save = NULL;
  char *token;

  copy_string(buffer, sizeof(buffer), arg);
  token = strtok_r(buffer, ",", &save);
  while (token != NULL) {
    int index;

    trim_in_place(token);
    if (token[0] == '\0') {
      token = strtok_r(NULL, ",", &save);
      continue;
    }

    index = find_field_index(token);
    if (index < 0) {
      snprintf(error, error_size, "Unknown field: %s", token);
      return false;
    }
    if (!add_selected_field(options, (size_t) index)) {
      snprintf(error, error_size, "Too many fields requested");
      return false;
    }

    token = strtok_r(NULL, ",", &save);
  }

  return true;
}

static size_t collect_active_fields(const OutputOptions *options, bool for_json,
                                    size_t *indices, size_t max_indices) {
  size_t count = 0;
  size_t i;

  if (options->selected_count > 0) {
    for (i = 0; i < options->selected_count && count < max_indices; i++) {
      indices[count++] = options->selected_indices[i];
    }
    return count;
  }

  for (i = 0; i < ARRAY_LEN(FIELD_DEFS) && count < max_indices; i++) {
    if (for_json || FIELD_DEFS[i].default_visible) {
      indices[count++] = i;
    }
  }

  return count;
}

static void build_kv(char *out, size_t out_size, const Colors *colors,
                     const char *key, const char *value, size_t label_width) {
  char label[64];

  snprintf(label, sizeof(label), "%s:", key);
  snprintf(out, out_size, "%s%-*s%s %s", colors->c1, (int) label_width,
           label, colors->reset, value);
}

static size_t build_text_lines(const SystemInfo *info, const Colors *colors,
                               const OutputOptions *options,
                               char lines[MAX_TEXT_LINES][512]) {
  size_t indices[ARRAY_LEN(FIELD_DEFS)];
  size_t field_count;
  size_t line_count = 0;
  size_t label_width = 0;
  size_t i;

  field_count = collect_active_fields(options, false, indices, ARRAY_LEN(indices));
  for (i = 0; i < field_count; i++) {
    size_t len = strlen(FIELD_DEFS[indices[i]].label) + 1;
    if (len > label_width) {
      label_width = len;
    }
  }

  if (options->selected_count == 0) {
    char header[160];
    char separator[160];

    snprintf(header, sizeof(header), "%s@%s", info->username, info->hostname);
    snprintf(lines[line_count++], sizeof(lines[0]), "%s%s%s",
             colors->c3, header, colors->reset);
    if (!options->compact) {
      memset(separator, '-', strlen(header));
      separator[strlen(header)] = '\0';
      snprintf(lines[line_count++], sizeof(lines[0]), "%s%s%s",
               colors->c3, separator, colors->reset);
      lines[line_count++][0] = '\0';
    }
  }

  for (i = 0; i < field_count && line_count < MAX_TEXT_LINES; i++) {
    build_kv(lines[line_count++], sizeof(lines[0]), colors,
             FIELD_DEFS[indices[i]].label, field_value(info, indices[i]), label_width);
  }

  return line_count;
}

static void print_logo_output(char lines[MAX_TEXT_LINES][512], size_t line_count,
                              const Colors *colors) {
  char logo_lines[ARRAY_LEN(RAW_LOGO)][256];
  size_t logo_width = 0;
  size_t logo_rows = ARRAY_LEN(RAW_LOGO);
  size_t rows = logo_rows;
  size_t line_start = 0;
  size_t i;

  for (i = 0; i < logo_rows; i++) {
    size_t len = strlen(RAW_LOGO[i]);
    if (len > logo_width) {
      logo_width = len;
    }
    snprintf(logo_lines[i], sizeof(logo_lines[i]), "%s%s%s",
             colors->c2, RAW_LOGO[i], colors->reset);
  }

  if (logo_rows > line_count) {
    line_start = (logo_rows - line_count) / 2;
  }
  if (line_start + line_count > rows) {
    rows = line_start + line_count;
  }

  for (i = 0; i < rows; i++) {
    const char *raw = i < logo_rows ? RAW_LOGO[i] : "";
    const char *logo = i < logo_rows ? logo_lines[i] : "";
    const char *text = "";
    size_t pad_width = logo_width - strlen(raw) + 4;
    size_t pad_idx;

    if (i >= line_start && i < line_start + line_count) {
      text = lines[i - line_start];
    }

    fputs(logo, stdout);
    for (pad_idx = 0; pad_idx < pad_width; pad_idx++) {
      fputc(' ', stdout);
    }
    fputs(text, stdout);
    fputc('\n', stdout);
  }
}

static void print_plain_output(const SystemInfo *info, const Colors *colors,
                               const OutputOptions *options) {
  char lines[MAX_TEXT_LINES][512];
  size_t line_count;
  size_t i;

  line_count = build_text_lines(info, colors, options, lines);
  if (options->show_logo) {
    print_logo_output(lines, line_count, colors);
    return;
  }

  for (i = 0; i < line_count; i++) {
    fputs(lines[i], stdout);
    fputc('\n', stdout);
  }
}

static void print_json_string(FILE *stream, const char *value) {
  const unsigned char *p = (const unsigned char *) value;

  fputc('"', stream);
  while (*p != '\0') {
    switch (*p) {
      case '\\':
        fputs("\\\\", stream);
        break;
      case '"':
        fputs("\\\"", stream);
        break;
      case '\n':
        fputs("\\n", stream);
        break;
      case '\r':
        fputs("\\r", stream);
        break;
      case '\t':
        fputs("\\t", stream);
        break;
      default:
        if (*p < 0x20) {
          fprintf(stream, "\\u%04x", *p);
        } else {
          fputc(*p, stream);
        }
        break;
    }
    p++;
  }
  fputc('"', stream);
}

static void print_json_output(const SystemInfo *info, const OutputOptions *options) {
  size_t indices[ARRAY_LEN(FIELD_DEFS)];
  size_t count;
  size_t i;

  count = collect_active_fields(options, true, indices, ARRAY_LEN(indices));
  fputc('{', stdout);
  for (i = 0; i < count; i++) {
    if (i > 0) {
      fputs(", ", stdout);
    }
    print_json_string(stdout, FIELD_DEFS[indices[i]].json_key);
    fputs(": ", stdout);
    print_json_string(stdout, field_value(info, indices[i]));
  }
  fputs("}\n", stdout);
}

static void list_fields(FILE *stream) {
  size_t i;

  for (i = 0; i < ARRAY_LEN(FIELD_DEFS); i++) {
    fprintf(stream, "%s\n", FIELD_DEFS[i].name);
  }
}

static void usage(FILE *stream, const char *argv0) {
  const char *prog = base_name(argv0);

  fprintf(stream,
          "%s - tiny neofetch-style system summary\n\n"
          "Usage:\n"
          "  %s\n"
          "  %s [options]\n\n"
          "Options:\n"
          "  --no-color       Disable ANSI colors\n"
          "  --no-logo        Disable the logo column\n"
          "  --compact        Compact text output (implies --no-logo)\n"
          "  --json           Print JSON\n"
          "  --field NAME     Print only a field (repeat or use commas)\n"
          "  --list-fields    List selectable fields\n"
          "  -h, --help       Show this help\n",
          prog, prog, prog);
}

int main(int argc, char **argv) {
  Colors colors = {
    .use_color = true,
    .c1 = "\033[1;36m",
    .c2 = "\033[1;32m",
    .c3 = "\033[1;35m",
    .reset = "\033[0m"
  };
  OutputOptions options = {
    .show_logo = true,
    .compact = false,
    .json = false,
    .selected_count = 0
  };
  SystemInfo info;
  const char *no_color_env = getenv("NO_COLOR");
  int i;

  memset(&info, 0, sizeof(info));

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      usage(stdout, argv[0]);
      return 0;
    }
    if (strcmp(argv[i], "--no-color") == 0) {
      colors.use_color = false;
      continue;
    }
    if (strcmp(argv[i], "--no-logo") == 0) {
      options.show_logo = false;
      continue;
    }
    if (strcmp(argv[i], "--compact") == 0) {
      options.compact = true;
      options.show_logo = false;
      continue;
    }
    if (strcmp(argv[i], "--json") == 0) {
      options.json = true;
      options.show_logo = false;
      colors.use_color = false;
      continue;
    }
    if (strcmp(argv[i], "--list-fields") == 0) {
      list_fields(stdout);
      return 0;
    }
    if (strcmp(argv[i], "--field") == 0) {
      char error[128];

      if (i + 1 >= argc) {
        fprintf(stderr, "--field requires a value\n\n");
        usage(stderr, argv[0]);
        return 1;
      }
      if (!add_field_argument(&options, argv[++i], error, sizeof(error))) {
        fprintf(stderr, "%s\n\n", error);
        usage(stderr, argv[0]);
        return 1;
      }
      continue;
    }

    fprintf(stderr, "Unknown argument: %s\n\n", argv[i]);
    usage(stderr, argv[0]);
    return 1;
  }

  if (!isatty(STDOUT_FILENO) ||
      (no_color_env != NULL && no_color_env[0] != '\0')) {
    colors.use_color = false;
  }

  if (!colors.use_color) {
    colors.c1 = "";
    colors.c2 = "";
    colors.c3 = "";
    colors.reset = "";
  }

  fill_system_info(&info);
  if (options.json) {
    print_json_output(&info, &options);
  } else {
    print_plain_output(&info, &colors, &options);
  }

  return 0;
}
