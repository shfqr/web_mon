#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <utmp.h>

#define MAX_IFACES 16
#define NAME_LEN 32
#define MAX_PROCS 64
#define MAX_CORES 128
#define PROC_NAME_LEN 64
#define CLIENT_TIMEOUT_SEC 5
#define TOKEN_CONFIG_PATH "/etc/webmon.conf"

struct CpuSample {
    unsigned long long total;
    unsigned long long idle;
};

struct MemoryStats {
    unsigned long long total;
    unsigned long long available;
    unsigned long long swap_total;
    unsigned long long swap_free;
};

struct DiskStats {
    char path[256];
    unsigned long long total;
    unsigned long long used;
    double percent;
};

struct NetSample {
    char name[NAME_LEN];
    unsigned long long rx;
    unsigned long long tx;
};

struct NetRateEntry {
    char name[NAME_LEN];
    double rx_rate;
    double tx_rate;
};

struct ProcTimes {
    int pid;
    char name[PROC_NAME_LEN];
    unsigned long long ticks;
};

struct Stats {
    double cpu_percent;
    double core_percents[MAX_CORES];
    int core_count;
    int has_entropy;
    unsigned long entropy_avail;
    int has_files;
    unsigned long file_used;
    unsigned long file_max;
    int has_temp;
    double temp_c;
    int has_hostname;
    char hostname[64];
    double loadavg[3];
    struct MemoryStats mem;
    struct DiskStats disk;
    struct NetRateEntry net[MAX_IFACES];
    int net_count;
    double uptime_seconds;
    int user_count;
    struct ProcessUsage {
        int pid;
        char name[PROC_NAME_LEN];
        double percent;
    } procs[MAX_PROCS];
    int proc_count;
};

struct SharedState {
    struct Stats stats;
    int has_stats;
    pthread_mutex_t lock;
};

static void handle_http_client(int client_fd, struct SharedState *state, double refresh, const char *token);

struct ClientQueue {
    int fds[64];
    int head;
    int tail;
    int count;
    int stop;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
};

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static void msleep(double seconds) {
    if (seconds <= 0) {
        return;
    }
    struct timespec ts;
    ts.tv_sec = (time_t)seconds;
    ts.tv_nsec = (long)((seconds - ts.tv_sec) * 1e9);
    nanosleep(&ts, NULL);
}

static int read_token_file(const char *path, char *out, size_t out_size) {
    if (!path || !out || out_size == 0) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    while (fgets(line, sizeof line, f)) {
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '\0' || *p == '\n' || *p == '#' || *p == ';') continue;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        char *key_end = eq;
        while (key_end > p && isspace((unsigned char)key_end[-1])) key_end--;
        size_t key_len = (size_t)(key_end - p);
        if (key_len != 5 || strncasecmp(p, "token", 5) != 0) continue;
        char *val = eq + 1;
        while (*val && isspace((unsigned char)*val)) val++;
        char *val_end = val + strcspn(val, "\r\n");
        while (val_end > val && isspace((unsigned char)val_end[-1])) val_end--;
        if (val_end > val && (*val == '\'' || *val == '"') && val_end[-1] == *val) {
            val++;
            val_end--;
        }
        if (val_end <= val) continue;
        size_t val_len = (size_t)(val_end - val);
        if (val_len >= out_size) val_len = out_size - 1;
        memcpy(out, val, val_len);
        out[val_len] = '\0';
        fclose(f);
        return 0;
    }
    fclose(f);
    return -1;
}

static int parse_cpu_line(const char *line, struct CpuSample *out) {
    unsigned long long user = 0, nice = 0, system = 0, idle = 0, iowait = 0;
    unsigned long long irq = 0, softirq = 0, steal = 0, guest = 0, guest_nice = 0;
    int parsed = 0;
    if (strncmp(line, "cpu ", 4) == 0) {
        parsed = sscanf(
            line,
            "cpu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
            &user,
            &nice,
            &system,
            &idle,
            &iowait,
            &irq,
            &softirq,
            &steal,
            &guest,
            &guest_nice);
    } else {
        parsed = sscanf(
            line,
            "cpu%*d %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
            &user,
            &nice,
            &system,
            &idle,
            &iowait,
            &irq,
            &softirq,
            &steal,
            &guest,
            &guest_nice);
    }
    if (parsed < 4) return -1;
    unsigned long long idle_time = idle + iowait;
    unsigned long long total = user + nice + system + idle + iowait + irq + softirq + steal + guest + guest_nice;
    out->idle = idle_time;
    out->total = total;
    return 0;
}

static int read_cpu_samples(struct CpuSample *total, struct CpuSample *cores, int *core_count) {
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return -1;
    char line[256];
    int count = 0;
    int got_total = 0;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "cpu", 3) != 0) break;
        if (strncmp(line, "cpu ", 4) == 0) {
            if (parse_cpu_line(line, total) == 0) got_total = 1;
        } else {
            if (count < MAX_CORES && parse_cpu_line(line, &cores[count]) == 0) {
                count++;
            }
        }
    }
    fclose(f);
    *core_count = count;
    return got_total ? 0 : -1;
}

static double compute_cpu_percent(const struct CpuSample *prev, const struct CpuSample *curr) {
    unsigned long long total_delta = curr->total - prev->total;
    unsigned long long idle_delta = curr->idle - prev->idle;
    if (total_delta == 0) {
        return 0.0;
    }
    double busy = (double)(total_delta - idle_delta);
    double pct = (busy / (double)total_delta) * 100.0;
    if (pct < 0.0) pct = 0.0;
    if (pct > 100.0) pct = 100.0;
    return pct;
}

static int read_meminfo(struct MemoryStats *out) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;
    char key[64];
    unsigned long long value = 0;
    int found = 0;
    while (fscanf(f, "%63[^:]: %llu kB\n", key, &value) == 2) {
        if (strcmp(key, "MemTotal") == 0) {
            out->total = value * 1024ULL;
            found++;
        } else if (strcmp(key, "MemAvailable") == 0) {
            out->available = value * 1024ULL;
            found++;
        } else if (strcmp(key, "SwapTotal") == 0) {
            out->swap_total = value * 1024ULL;
            found++;
        } else if (strcmp(key, "SwapFree") == 0) {
            out->swap_free = value * 1024ULL;
            found++;
        }
        if (found == 4) break;
    }
    fclose(f);
    return (found == 4) ? 0 : -1;
}

static int read_entropy(unsigned long *out) {
    FILE *f = fopen("/proc/sys/kernel/random/entropy_avail", "r");
    if (!f) return -1;
    unsigned long v = 0;
    if (fscanf(f, "%lu", &v) != 1) {
        fclose(f);
        return -1;
    }
    fclose(f);
    *out = v;
    return 0;
}

static int read_file_handles(unsigned long *used, unsigned long *max) {
    FILE *f = fopen("/proc/sys/fs/file-nr", "r");
    if (!f) return -1;
    unsigned long alloc = 0, free = 0, limit = 0;
    int ok = fscanf(f, "%lu %lu %lu", &alloc, &free, &limit);
    fclose(f);
    if (ok != 3) return -1;
    *used = alloc > free ? alloc - free : 0;
    *max = limit;
    return 0;
}

static int read_temperature(double *temp_c) {
    char path[128];
    for (int i = 0; i < 8; i++) {
        snprintf(path, sizeof path, "/sys/class/thermal/thermal_zone%d/temp", i);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        long t = 0;
        int ok = fscanf(f, "%ld", &t);
        fclose(f);
        if (ok == 1) {
            double v = (double)t;
            if (v > 200.0) v /= 1000.0;
            *temp_c = v;
            return 0;
        }
    }
    return -1;
}

static int read_disk(const char *path, struct DiskStats *out) {
    struct statvfs vfs;
    if (statvfs(path, &vfs) != 0) {
        return -1;
    }
    unsigned long long total = (unsigned long long)vfs.f_frsize * (unsigned long long)vfs.f_blocks;
    unsigned long long free = (unsigned long long)vfs.f_frsize * (unsigned long long)vfs.f_bfree;
    unsigned long long used = total - free;
    double pct = (total == 0) ? 0.0 : ((double)used / (double)total) * 100.0;
    strncpy(out->path, path, sizeof(out->path) - 1);
    out->path[sizeof(out->path) - 1] = '\0';
    out->total = total;
    out->used = used;
    out->percent = pct;
    return 0;
}

static double read_uptime_seconds(void) {
    FILE *f = fopen("/proc/uptime", "r");
    if (!f) return 0.0;
    double up = 0.0;
    if (fscanf(f, "%lf", &up) != 1) {
        up = 0.0;
    }
    fclose(f);
    return up;
}

static int count_users(void) {
    struct utmp *ut;
    int count = 0;
    setutxent();
    while ((ut = getutxent()) != NULL) {
        if (ut->ut_type == USER_PROCESS) {
            count++;
        }
    }
    endutxent();
    if (count > 0) return count;

    /* Fallback: count session leaders with a TTY from /proc when utmp is empty (e.g., Alpine) */
    DIR *dir = opendir("/proc");
    if (!dir) return 0;
    int sessions[512];
    int sess_count = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
        int pid = atoi(ent->d_name);
        if (pid <= 0) continue;
        char stat_path[64];
        snprintf(stat_path, sizeof stat_path, "/proc/%d/stat", pid);
        FILE *f = fopen(stat_path, "r");
        if (!f) continue;
        char buf[512];
        if (!fgets(buf, sizeof buf, f)) {
            fclose(f);
            continue;
        }
        fclose(f);
        char *rparen = strrchr(buf, ')');
        if (!rparen) continue;
        char *rest = rparen + 2;
        int field = 0;
        int tty_nr = 0;
        int session = 0;
        char *tok = strtok(rest, " ");
        while (tok) {
            field++;
            if (field == 4) { /* session id */
                session = atoi(tok);
            } else if (field == 5) { /* tty_nr */
                tty_nr = atoi(tok);
                break;
            }
            tok = strtok(NULL, " ");
        }
        if (tty_nr <= 0 || session <= 0) continue;
        if (pid != session) continue; /* only session leaders */
        int dup = 0;
        for (int i = 0; i < sess_count; i++) {
            if (sessions[i] == session) {
                dup = 1;
                break;
            }
        }
        if (!dup && sess_count < (int)(sizeof sessions / sizeof sessions[0])) {
            sessions[sess_count++] = session;
        }
    }
    closedir(dir);
    return sess_count;
}

static int read_proc_times(struct ProcTimes **list, int *count) {
    DIR *dir = opendir("/proc");
    if (!dir) return -1;
    int capacity = 256;
    int n = 0;
    struct ProcTimes *items = malloc(sizeof(struct ProcTimes) * (size_t)capacity);
    if (!items) {
        closedir(dir);
        return -1;
    }
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
        int pid = atoi(ent->d_name);
        if (pid <= 0) continue;
        char path[64];
        snprintf(path, sizeof path, "/proc/%d/stat", pid);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        char line[512];
        if (!fgets(line, sizeof line, f)) {
            fclose(f);
            continue;
        }
        fclose(f);
        char *lparen = strchr(line, '(');
        char *rparen = strrchr(line, ')');
        if (!lparen || !rparen || rparen <= lparen + 1) continue;
        char namebuf[PROC_NAME_LEN];
        size_t name_len = (size_t)(rparen - lparen - 1);
        if (name_len >= sizeof namebuf) name_len = sizeof namebuf - 1;
        memcpy(namebuf, lparen + 1, name_len);
        namebuf[name_len] = '\0';
        char *rest = rparen + 2;
        int idx = 0;
        unsigned long long utime = 0, stime = 0;
        char *token = strtok(rest, " ");
        while (token) {
            idx++;
            if (idx == 12) utime = strtoull(token, NULL, 10);
            else if (idx == 13) stime = strtoull(token, NULL, 10);
            if (idx >= 13) break;
            token = strtok(NULL, " ");
        }
        if (idx < 13) continue;
        if (n >= capacity) {
            capacity *= 2;
            struct ProcTimes *tmp = realloc(items, sizeof(struct ProcTimes) * (size_t)capacity);
            if (!tmp) {
                free(items);
                closedir(dir);
                return -1;
            }
            items = tmp;
        }
        items[n].pid = pid;
        strncpy(items[n].name, namebuf, PROC_NAME_LEN - 1);
        items[n].name[PROC_NAME_LEN - 1] = '\0';
        items[n].ticks = utime + stime;
        n++;
    }
    closedir(dir);
    *list = items;
    *count = n;
    return 0;
}

static int find_proc(const struct ProcTimes *list, int count, int pid) {
    for (int i = 0; i < count; i++) {
        if (list[i].pid == pid) return i;
    }
    return -1;
}

static int compare_proc_usage(const void *a, const void *b) {
    const struct ProcessUsage *pa = (const struct ProcessUsage *)a;
    const struct ProcessUsage *pb = (const struct ProcessUsage *)b;
    if (pb->percent > pa->percent) return 1;
    if (pb->percent < pa->percent) return -1;
    return 0;
}

static void compute_proc_usage(
    const struct ProcTimes *start, int start_count,
    const struct ProcTimes *end, int end_count,
    unsigned long long total_delta,
    struct ProcessUsage *out, int *out_count) {
    *out_count = 0;
    if (total_delta == 0 || end_count == 0) return;
    struct ProcessUsage *tmp = malloc(sizeof(struct ProcessUsage) * (size_t)end_count);
    if (!tmp) return;
    int tmp_count = 0;
    for (int i = 0; i < end_count; i++) {
        int idx = find_proc(start, start_count, end[i].pid);
        if (idx < 0) continue;
        unsigned long long delta = (end[i].ticks > start[idx].ticks) ? (end[i].ticks - start[idx].ticks) : 0;
        if (delta == 0) continue;
        double pct = ((double)delta / (double)total_delta) * 100.0;
        if (pct < 1.0) continue;
        tmp[tmp_count].pid = end[i].pid;
        strncpy(tmp[tmp_count].name, end[i].name, PROC_NAME_LEN - 1);
        tmp[tmp_count].name[PROC_NAME_LEN - 1] = '\0';
        tmp[tmp_count].percent = pct;
        tmp_count++;
    }
    qsort(tmp, (size_t)tmp_count, sizeof(struct ProcessUsage), compare_proc_usage);
    int limit = tmp_count < MAX_PROCS ? tmp_count : MAX_PROCS;
    for (int i = 0; i < limit; i++) {
        out[i] = tmp[i];
    }
    *out_count = limit;
    free(tmp);
}

static bool iface_allowed(const char *name, char **filters, int filter_count) {
    if (filter_count == 0) {
        return strcmp(name, "lo") != 0;
    }
    for (int i = 0; i < filter_count; i++) {
        if (strcmp(name, filters[i]) == 0) return true;
    }
    return false;
}

static int read_net_samples(struct NetSample entries[], int *count, char **filters, int filter_count) {
    FILE *f = fopen("/proc/net/dev", "r");
    if (!f) return -1;
    char line[256];
    /* skip headers */
    if (!fgets(line, sizeof line, f) || !fgets(line, sizeof line, f)) {
        fclose(f);
        return -1;
    }
    int idx = 0;
    while (fgets(line, sizeof line, f) && idx < MAX_IFACES) {
        char iface[NAME_LEN];
        unsigned long long rx = 0, tx = 0;
        unsigned long long d[14] = {0};
        int matched = sscanf(
            line,
            " %31[^:]: %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
            iface,
            &rx,
            &d[0], &d[1], &d[2], &d[3], &d[4], &d[5], &d[6],
            &tx,
            &d[7], &d[8], &d[9], &d[10], &d[11], &d[12], &d[13]);
        if (matched != 17) continue;
        if (!iface_allowed(iface, filters, filter_count)) continue;
        strncpy(entries[idx].name, iface, NAME_LEN - 1);
        entries[idx].name[NAME_LEN - 1] = '\0';
        entries[idx].rx = rx;
        entries[idx].tx = tx;
        idx++;
    }
    fclose(f);
    *count = idx;
    return 0;
}

static int find_net_sample(const struct NetSample *list, int count, const char *name) {
    for (int i = 0; i < count; i++) {
        if (strcmp(list[i].name, name) == 0) return i;
    }
    return -1;
}

static int sample_stats(double interval, const char *disk_path, char **filters, int filter_count, struct Stats *out) {
    struct CpuSample cpu_start, cpu_end;
    struct CpuSample cores_start[MAX_CORES], cores_end[MAX_CORES];
    int core_count_start = 0, core_count_end = 0;
    struct NetSample net_start[MAX_IFACES], net_end[MAX_IFACES];
    int net_start_count = 0, net_end_count = 0;
    struct ProcTimes *procs_start = NULL;
    struct ProcTimes *procs_end = NULL;
    int procs_start_count = 0, procs_end_count = 0;

    if (read_cpu_samples(&cpu_start, cores_start, &core_count_start) != 0) return -1;
    read_net_samples(net_start, &net_start_count, filters, filter_count);
    read_proc_times(&procs_start, &procs_start_count);
    if (read_entropy(&out->entropy_avail) == 0) {
        out->has_entropy = 1;
    } else {
        out->has_entropy = 0;
    }
    if (read_file_handles(&out->file_used, &out->file_max) == 0) {
        out->has_files = 1;
    } else {
        out->has_files = 0;
    }
    out->hostname[0] = '\0';
    if (gethostname(out->hostname, sizeof out->hostname) == 0) {
        out->hostname[sizeof out->hostname - 1] = '\0';
        out->has_hostname = 1;
    } else {
        out->has_hostname = 0;
    }
    if (read_temperature(&out->temp_c) == 0) {
        out->has_temp = 1;
    } else {
        out->has_temp = 0;
    }

    msleep(interval);

    if (read_cpu_samples(&cpu_end, cores_end, &core_count_end) != 0) {
        free(procs_start);
        return -1;
    }
    read_net_samples(net_end, &net_end_count, filters, filter_count);
    read_proc_times(&procs_end, &procs_end_count);

    out->cpu_percent = compute_cpu_percent(&cpu_start, &cpu_end);
    out->core_count = core_count_start < core_count_end ? core_count_start : core_count_end;
    if (out->core_count > MAX_CORES) out->core_count = MAX_CORES;
    for (int i = 0; i < out->core_count; i++) {
        out->core_percents[i] = compute_cpu_percent(&cores_start[i], &cores_end[i]);
    }

    if (getloadavg(out->loadavg, 3) != 3) {
        out->loadavg[0] = out->loadavg[1] = out->loadavg[2] = 0.0;
    }
    read_meminfo(&out->mem);
    read_disk(disk_path, &out->disk);
    out->uptime_seconds = read_uptime_seconds();
    out->user_count = count_users();
    compute_proc_usage(procs_start, procs_start_count, procs_end, procs_end_count, cpu_end.total - cpu_start.total, out->procs, &out->proc_count);
    free(procs_start);
    free(procs_end);

    out->net_count = 0;
    for (int i = 0; i < net_end_count && out->net_count < MAX_IFACES; i++) {
        int idx = find_net_sample(net_start, net_start_count, net_end[i].name);
        if (idx < 0) continue;
        double rx_delta = (double)(net_end[i].rx - net_start[idx].rx);
        double tx_delta = (double)(net_end[i].tx - net_start[idx].tx);
        double denom = interval > 0 ? interval : 0.001;
        strncpy(out->net[out->net_count].name, net_end[i].name, NAME_LEN - 1);
        out->net[out->net_count].name[NAME_LEN - 1] = '\0';
        out->net[out->net_count].rx_rate = rx_delta / denom;
        out->net[out->net_count].tx_rate = tx_delta / denom;
        out->net_count++;
    }
    return 0;
}

static void format_bytes(unsigned long long bytes, char *buf, size_t bufsize) {
    const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double v = (double)bytes;
    int idx = 0;
    while (v >= 1024.0 && idx < 4) {
        v /= 1024.0;
        idx++;
    }
    snprintf(buf, bufsize, "%.1f %s", v, units[idx]);
}

static void format_uptime(double seconds, char *buf, size_t bufsize) {
    unsigned long long s = (unsigned long long)seconds;
    unsigned long long days = s / 86400ULL;
    unsigned long long hours = (s % 86400ULL) / 3600ULL;
    unsigned long long minutes = (s % 3600ULL) / 60ULL;
    if (days > 0) {
        snprintf(buf, bufsize, "%llud %lluh %llum", days, hours, minutes);
    } else if (hours > 0) {
        snprintf(buf, bufsize, "%lluh %llum", hours, minutes);
    } else {
        snprintf(buf, bufsize, "%llum", minutes);
    }
}

static void appendf(char *buf, size_t bufsize, size_t *off, const char *fmt, ...) {
    if (*off >= bufsize) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *off, bufsize - *off, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n >= bufsize - *off) {
        *off = bufsize - 1;
    } else {
        *off += (size_t)n;
    }
}

static void append_json_string(char *buf, size_t bufsize, size_t *off, const char *s) {
    appendf(buf, bufsize, off, "\"");
    if (!s) s = "";
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        switch (c) {
            case '\"':
                appendf(buf, bufsize, off, "\\\"");
                break;
            case '\\':
                appendf(buf, bufsize, off, "\\\\");
                break;
            case '\b':
                appendf(buf, bufsize, off, "\\b");
                break;
            case '\f':
                appendf(buf, bufsize, off, "\\f");
                break;
            case '\n':
                appendf(buf, bufsize, off, "\\n");
                break;
            case '\r':
                appendf(buf, bufsize, off, "\\r");
                break;
            case '\t':
                appendf(buf, bufsize, off, "\\t");
                break;
            default:
                if (c < 0x20) {
                    appendf(buf, bufsize, off, "\\u%04x", c);
                } else {
                    appendf(buf, bufsize, off, "%c", c);
                }
        }
    }
    appendf(buf, bufsize, off, "\"");
}

static void append_html_escaped(char *buf, size_t bufsize, size_t *off, const char *s) {
    if (!s) return;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
            case '&':
                appendf(buf, bufsize, off, "&amp;");
                break;
            case '<':
                appendf(buf, bufsize, off, "&lt;");
                break;
            case '>':
                appendf(buf, bufsize, off, "&gt;");
                break;
            case '"':
                appendf(buf, bufsize, off, "&quot;");
                break;
            case '\'':
                appendf(buf, bufsize, off, "&#39;");
                break;
            default:
                appendf(buf, bufsize, off, "%c", *p);
        }
    }
}

static char **split_interfaces(const char *arg, int *count) {
    if (!arg) {
        *count = 0;
        return NULL;
    }
    char *copy = strdup(arg);
    if (!copy) return NULL;
    char **list = calloc(MAX_IFACES, sizeof(char *));
    if (!list) {
        free(copy);
        return NULL;
    }
    int idx = 0;
    char *token = strtok(copy, ",");
    while (token && idx < MAX_IFACES) {
        list[idx++] = strdup(token);
        token = strtok(NULL, ",");
    }
    *count = idx;
    free(copy);
    return list;
}

static void free_interfaces(char **list, int count) {
    if (!list) return;
    for (int i = 0; i < count; i++) {
        free(list[i]);
    }
    free(list);
}

struct SamplerArgs {
    double interval;
    const char *disk_path;
    char **filters;
    int filter_count;
    struct SharedState *state;
};

struct WorkerArgs {
    struct ClientQueue *queue;
    struct SharedState *state;
    double refresh;
    const char *token;
};

static void queue_init(struct ClientQueue *q) {
    memset(q, 0, sizeof(*q));
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->not_empty, NULL);
}

static void queue_destroy(struct ClientQueue *q) {
    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->not_empty);
}

static int queue_push(struct ClientQueue *q, int fd) {
    pthread_mutex_lock(&q->lock);
    if (q->count >= (int)(sizeof(q->fds) / sizeof(q->fds[0]))) {
        pthread_mutex_unlock(&q->lock);
        return -1;
    }
    q->fds[q->tail] = fd;
    q->tail = (q->tail + 1) % (int)(sizeof(q->fds) / sizeof(q->fds[0]));
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
    return 0;
}

static int queue_pop(struct ClientQueue *q, int *fd) {
    pthread_mutex_lock(&q->lock);
    while (q->count == 0 && !q->stop) {
        pthread_cond_wait(&q->not_empty, &q->lock);
    }
    if (q->count == 0 && q->stop) {
        pthread_mutex_unlock(&q->lock);
        return -1;
    }
    *fd = q->fds[q->head];
    q->head = (q->head + 1) % (int)(sizeof(q->fds) / sizeof(q->fds[0]));
    q->count--;
    pthread_mutex_unlock(&q->lock);
    return 0;
}

static void queue_stop(struct ClientQueue *q) {
    pthread_mutex_lock(&q->lock);
    q->stop = 1;
    pthread_cond_broadcast(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
}

static void set_client_timeouts(int fd) {
    struct timeval tv;
    tv.tv_sec = CLIENT_TIMEOUT_SEC;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

static ssize_t recv_request(int fd, char *buf, size_t bufsize) {
    if (bufsize == 0) return -1;
    size_t off = 0;
    buf[0] = '\0';
    while (off < bufsize - 1) {
        ssize_t n = recv(fd, buf + off, bufsize - 1 - off, 0);
        if (n <= 0) return n;
        off += (size_t)n;
        buf[off] = '\0';
        if (strstr(buf, "\r\n\r\n")) break;
    }
    return (ssize_t)off;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static size_t url_decode(const char *src, size_t len, char *dst, size_t dst_size) {
    size_t di = 0;
    for (size_t si = 0; si < len && di + 1 < dst_size; si++) {
        if (src[si] == '%' && si + 2 < len) {
            int hi = hex_value(src[si + 1]);
            int lo = hex_value(src[si + 2]);
            if (hi >= 0 && lo >= 0) {
                dst[di++] = (char)((hi << 4) | lo);
                si += 2;
                continue;
            }
        }
        dst[di++] = src[si];
    }
    dst[di] = '\0';
    return di;
}

static int token_matches_query(const char *path, const char *token) {
    const char *q = strchr(path, '?');
    if (!q) return 0;
    q++;
    while (*q) {
        const char *key = q;
        const char *amp = strchr(q, '&');
        if (!amp) amp = q + strlen(q);
        const char *eq = memchr(key, '=', (size_t)(amp - key));
        if (eq) {
            size_t key_len = (size_t)(eq - key);
            if (key_len == 5 && strncmp(key, "token", 5) == 0) {
                char value[256];
                size_t val_len = (size_t)(amp - eq - 1);
                url_decode(eq + 1, val_len, value, sizeof value);
                if (strcmp(value, token) == 0) return 1;
            }
        }
        q = (*amp == '&') ? amp + 1 : amp;
    }
    return 0;
}

static int token_matches_header(const char *req, const char *token) {
    const char *p = strstr(req, "\r\n");
    if (!p) return 0;
    p += 2;
    while (*p && !(p[0] == '\r' && p[1] == '\n')) {
        const char *line_end = strstr(p, "\r\n");
        if (!line_end) line_end = p + strlen(p);
        const char *colon = memchr(p, ':', (size_t)(line_end - p));
        if (colon) {
            size_t name_len = (size_t)(colon - p);
            if (name_len == 13 && strncasecmp(p, "X-WebMon-Token", name_len) == 0) {
                const char *val = colon + 1;
                while (val < line_end && (*val == ' ' || *val == '\t')) val++;
                size_t val_len = (size_t)(line_end - val);
                while (val_len > 0 && (val[val_len - 1] == ' ' || val[val_len - 1] == '\t')) {
                    val_len--;
                }
                if (strlen(token) == val_len && strncmp(val, token, val_len) == 0) return 1;
            }
        }
        if (*line_end == '\0') break;
        p = line_end + 2;
    }
    return 0;
}

static int is_authorized(const char *req, const char *path, const char *token) {
    if (!token || token[0] == '\0') return 1;
    if (token_matches_header(req, token)) return 1;
    if (token_matches_query(path, token)) return 1;
    return 0;
}

static void *sampler_thread(void *arg) {
    struct SamplerArgs *cfg = (struct SamplerArgs *)arg;
    while (!g_stop) {
        struct Stats s = {0};
        if (sample_stats(cfg->interval, cfg->disk_path, cfg->filters, cfg->filter_count, &s) == 0) {
            pthread_mutex_lock(&cfg->state->lock);
            cfg->state->stats = s;
            cfg->state->has_stats = 1;
            pthread_mutex_unlock(&cfg->state->lock);
        }
    }
    return NULL;
}

static void *worker_thread(void *arg) {
    struct WorkerArgs *cfg = (struct WorkerArgs *)arg;
    while (!g_stop) {
        int client_fd = -1;
        if (queue_pop(cfg->queue, &client_fd) != 0) {
            break;
        }
        if (client_fd >= 0) {
            handle_http_client(client_fd, cfg->state, cfg->refresh, cfg->token);
            close(client_fd);
        }
    }
    return NULL;
}

static void write_all(int fd, const char *buf, size_t len) {
    size_t written = 0;
    int flags = 0;
#ifdef MSG_NOSIGNAL
    flags = MSG_NOSIGNAL;
#endif
    while (written < len) {
        ssize_t n = send(fd, buf + written, len - written, flags);
        if (n <= 0) return;
        written += (size_t)n;
    }
}

static int is_metrics_path(const char *path) {
    if (!path) return 0;
    size_t len = strlen(path);
    const char *q = strchr(path, '?');
    if (q) len = (size_t)(q - path);
    while (len > 1 && path[len - 1] == '/') {
        len--;
    }
    if (len < 7) return 0;
    const char *p = path + len;
    while (p > path && p[-1] != '/') {
        p--;
    }
    size_t nlen = (size_t)((path + len) - p);
    return (nlen == 7 && strncmp(p, "metrics", 7) == 0);
}

static void render_json(const struct Stats *s, char *buf, size_t bufsize) {
    size_t off = 0;
    appendf(buf, bufsize, &off, "{ \"cpu_percent\": %.2f, \"cores\": [", s->cpu_percent);
    for (int i = 0; i < s->core_count; i++) {
        appendf(buf, bufsize, &off, "%s%.2f", (i == 0 ? "" : ", "), s->core_percents[i]);
    }
    appendf(buf, bufsize, &off,
            "], \"loadavg\": [%.2f, %.2f, %.2f], "
            "\"memory\": { \"total\": %llu, \"available\": %llu, \"swap_total\": %llu, \"swap_free\": %llu }, "
            "\"disk\": { \"path\": ",
            s->loadavg[0], s->loadavg[1], s->loadavg[2],
            s->mem.total, s->mem.available, s->mem.swap_total, s->mem.swap_free);
    append_json_string(buf, bufsize, &off, s->disk.path);
    appendf(buf, bufsize, &off,
            ", \"total\": %llu, \"used\": %llu, \"percent\": %.2f }, "
            "\"uptime_seconds\": %.0f, \"user_count\": %d, "
            "\"net\": {",
            s->disk.total, s->disk.used, s->disk.percent,
            s->uptime_seconds, s->user_count);
    for (int i = 0; i < s->net_count; i++) {
        appendf(buf, bufsize, &off, "%s", (i == 0 ? "" : ", "));
        append_json_string(buf, bufsize, &off, s->net[i].name);
        appendf(buf, bufsize, &off,
                ": {\"rx_rate\": %.2f, \"tx_rate\": %.2f}",
                s->net[i].rx_rate,
                s->net[i].tx_rate);
    }
    appendf(buf, bufsize, &off, " }, \"procs\": [");
    for (int i = 0; i < s->proc_count; i++) {
        appendf(buf, bufsize, &off,
                "%s{\"pid\": %d, \"name\": ",
                (i == 0 ? "" : ", "),
                s->procs[i].pid);
        append_json_string(buf, bufsize, &off, s->procs[i].name);
        appendf(buf, bufsize, &off, ", \"percent\": %.2f}", s->procs[i].percent);
    }
    appendf(buf, bufsize, &off, " ]");
    if (s->has_entropy) {
        appendf(buf, bufsize, &off, ", \"entropy\": %lu", s->entropy_avail);
    }
    if (s->has_files) {
        appendf(buf, bufsize, &off, ", \"files\": {\"used\": %lu, \"max\": %lu}", s->file_used, s->file_max);
    }
    if (s->has_temp) {
        appendf(buf, bufsize, &off, ", \"temp_c\": %.1f", s->temp_c);
    }
    if (s->has_hostname) {
        if (s->hostname[0] != '\0') {
            appendf(buf, bufsize, &off, ", \"hostname\": ");
            append_json_string(buf, bufsize, &off, s->hostname);
        }
    }
    appendf(buf, bufsize, &off, " }");
}

static void render_html(const struct Stats *s, double refresh, char *buf, size_t bufsize, const char *token) {
    char mem_used[32], mem_total[32], swap_used[32], swap_total[32], disk_used[32], disk_total[32];
    format_bytes(s->mem.total - s->mem.available, mem_used, sizeof mem_used);
    format_bytes(s->mem.total, mem_total, sizeof mem_total);
    format_bytes(s->mem.swap_total - s->mem.swap_free, swap_used, sizeof swap_used);
    format_bytes(s->mem.swap_total, swap_total, sizeof swap_total);
    format_bytes(s->disk.used, disk_used, sizeof disk_used);
    format_bytes(s->disk.total, disk_total, sizeof disk_total);

    char net_section[4096];
    size_t net_off = 0;
    double max_rate = 1.0;
    for (int i = 0; i < s->net_count; i++) {
        double r = s->net[i].rx_rate > s->net[i].tx_rate ? s->net[i].rx_rate : s->net[i].tx_rate;
        if (r > max_rate) max_rate = r;
    }
    if (s->net_count == 0) {
        appendf(net_section, sizeof net_section, &net_off,
                "<p id='net-empty'>No network traffic detected.</p><table id='net-table' style='display:none'></table>");
    } else {
        appendf(net_section, sizeof net_section, &net_off,
                "<table id='net-table'><tr><th>Interface</th><th>RX</th><th>TX</th></tr>");
        for (int i = 0; i < s->net_count && net_off < sizeof net_section; i++) {
            char rx_h[32], tx_h[32];
            format_bytes((unsigned long long)s->net[i].rx_rate, rx_h, sizeof rx_h);
            format_bytes((unsigned long long)s->net[i].tx_rate, tx_h, sizeof tx_h);
            int rx_pct = (int)((s->net[i].rx_rate / max_rate) * 100.0);
            int tx_pct = (int)((s->net[i].tx_rate / max_rate) * 100.0);
            if (rx_pct < 0) rx_pct = 0;
            if (rx_pct > 100) rx_pct = 100;
            if (tx_pct < 0) tx_pct = 0;
            if (tx_pct > 100) tx_pct = 100;
            appendf(net_section, sizeof net_section, &net_off, "<tr><td>");
            append_html_escaped(net_section, sizeof net_section, &net_off, s->net[i].name);
            appendf(net_section, sizeof net_section, &net_off,
                    "</td><td>%s/s<div class='bar'><div class='fill net-rx' style='width:%d%%'></div></div></td>"
                    "<td>%s/s<div class='bar'><div class='fill net-tx' style='width:%d%%'></div></div></td></tr>",
                    rx_h, rx_pct, tx_h, tx_pct);
        }
        appendf(net_section, sizeof net_section, &net_off,
                "</table><p id='net-empty' style='display:none'>No network traffic detected.</p>");
    }

    char *json_body = malloc(65536);
    const char *json_payload = "{}";
    if (json_body) {
        render_json(s, json_body, 65536);
        json_payload = json_body;
    }

    size_t off = 0;
    appendf(buf, bufsize, &off, "<!doctype html><html><head>");
    appendf(buf, bufsize, &off, "<meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'/>");
    appendf(buf, bufsize, &off, "<title>WebMon</title>");
    appendf(buf, bufsize, &off, "<style>");
    appendf(buf, bufsize, &off, ":root{--bg:#0c1118;--fg:#e5e9f0;--muted:#94a3b8;--card:#111827;--bar-bg:#1f2933;--accent-cpu:#f59e0b;--accent-mem:#a3e635;--accent-swap:#22d3ee;--accent-disk:#60a5fa;--accent-rx:#a78bfa;--accent-tx:#fb7185;}");
    appendf(buf, bufsize, &off, "[data-theme=\"light\"]{--bg:#f8fafc;--fg:#0f172a;--muted:#475569;--card:#e2e8f0;--bar-bg:#cbd5e1;--accent-cpu:#d97706;--accent-mem:#16a34a;--accent-swap:#06b6d4;--accent-disk:#2563eb;--accent-rx:#7c3aed;--accent-tx:#dc2626;}");
    appendf(buf, bufsize, &off, "body{font-family:monospace;background:var(--bg);color:var(--fg);padding:1rem;margin:0;}#toolbar{display:flex;align-items:center;justify-content:space-between;gap:0.5rem;}h1{margin:0;font-size:1.4rem;max-width:45vw;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}");
    appendf(buf, bufsize, &off, "#toolbar-meta{display:flex;align-items:center;gap:0.5rem;margin-left:auto;}");
    appendf(buf, bufsize, &off, ".pill{display:inline-flex;align-items:center;gap:0.25rem;background:var(--card);color:var(--fg);border:1px solid var(--bar-bg);padding:0.25rem 0.5rem;border-radius:999px;font-size:0.9rem;}");
    appendf(buf, bufsize, &off, "button{background:var(--bar-bg);color:var(--fg);border:1px solid var(--muted);padding:0.35rem 0.6rem;border-radius:6px;cursor:pointer;}button:hover{border-color:var(--fg);}section{margin:0 0 1rem 0;padding:0.75rem;border-radius:10px;background:var(--card);}");
    appendf(buf, bufsize, &off, "table{width:100%%;border-collapse:collapse;}th,td{text-align:left;padding:0.25rem 0.5rem;border-bottom:1px solid var(--bar-bg);vertical-align:middle;}th{color:var(--muted);}small{color:var(--muted);}.metric{color:var(--accent-mem);}.muted{color:var(--muted);}");
    appendf(buf, bufsize, &off, ".bar{width:100%%;height:10px;background:var(--bar-bg);border-radius:4px;overflow:hidden;margin-top:4px;}.fill{height:100%%;transition:width 0.2s ease;}.fill.cpu{background:var(--accent-cpu);}.fill.mem{background:var(--accent-mem);}.fill.swap{background:var(--accent-swap);}.fill.disk{background:var(--accent-disk);}.fill.net-rx{background:var(--accent-rx);}.fill.net-tx{background:var(--accent-tx);}");
    appendf(buf, bufsize, &off, ".core-row{display:flex;align-items:center;gap:0.35rem;margin:4px 0;font-size:0.9rem;}.core-name{min-width:46px;color:var(--muted);}.core-bar{flex:1;height:8px;background:var(--bar-bg);border-radius:4px;overflow:hidden;}.core-pct{text-align:right;width:56px;}");
    appendf(buf, bufsize, &off, ".graph{margin-top:6px;} .graph svg{width:100%%;height:80px;}#sys div{margin:3px 0;}");
    appendf(buf, bufsize, &off, "@media(max-width:640px){body{font-size:14px;padding:0.75rem;}table{font-size:13px;}h1{font-size:1.1rem;}#toolbar{flex-direction:row;align-items:center;}}");
    appendf(buf, bufsize, &off, "</style></head><body>");

    char up_text[64];
    format_uptime(s->uptime_seconds, up_text, sizeof up_text);
    char user_text[16];
    snprintf(user_text, sizeof user_text, "%d", s->user_count);
    const char *title = (s->has_hostname && s->hostname[0] != '\0') ? s->hostname : "WebMon";
    appendf(buf, bufsize, &off, "<div id='toolbar'><h1 title='");
    append_html_escaped(buf, bufsize, &off, title);
    appendf(buf, bufsize, &off, "'>");
    append_html_escaped(buf, bufsize, &off, title);
    appendf(buf, bufsize, &off, "</h1><div id='toolbar-meta'><span id='uptime-pill' class='pill'>⏱ %s</span><span id='users-pill' class='pill'>👥 %s</span></div></div>", up_text, user_text);
    appendf(buf, bufsize, &off, "<section><div id='cpu'>CPU: <span class='metric'>%.1f%%</span> | Load: %.2f / %.2f / %.2f</div>", s->cpu_percent, s->loadavg[0], s->loadavg[1], s->loadavg[2]);
    appendf(buf, bufsize, &off, "<div class='bar'><div class='fill cpu' style='width:%.1f%%'></div></div></section>", s->cpu_percent);
    appendf(buf, bufsize, &off, "<section><div>Processes (>=1%% CPU)</div><div id='procs'>");
    if (s->proc_count == 0) {
        appendf(buf, bufsize, &off, "<p id='procs-empty'>No processes above 1%% CPU.</p>");
    } else {
        appendf(buf, bufsize, &off, "<table id='procs-table'><tr><th>Name</th><th>PID</th><th>CPU</th></tr>");
        for (int i = 0; i < s->proc_count; i++) {
            appendf(buf, bufsize, &off, "<tr><td>");
            append_html_escaped(buf, bufsize, &off, s->procs[i].name);
            appendf(buf, bufsize, &off, "</td><td>%d</td><td>%.1f%%</td></tr>", s->procs[i].pid, s->procs[i].percent);
        }
        appendf(buf, bufsize, &off, "</table>");
    }
    appendf(buf, bufsize, &off, "</div></section>");
    appendf(buf, bufsize, &off, "<section><div>CPU Cores</div><div id='cores'>");
    if (s->core_count == 0) {
        appendf(buf, bufsize, &off, "<p id='cores-empty'>Per-core data unavailable.</p>");
    } else {
        for (int i = 0; i < s->core_count; i++) {
            appendf(buf, bufsize, &off, "<div class='core-row'><span class='core-name'>CPU%d</span><div class='core-bar'><div class='fill cpu' style='width:%.1f%%'></div></div><span class='core-pct'>%.1f%%</span></div>", i, s->core_percents[i], s->core_percents[i]);
        }
    }
    appendf(buf, bufsize, &off, "</div></section>");
    double mem_pct = s->mem.total ? ((double)(s->mem.total - s->mem.available) / (double)s->mem.total * 100.0) : 0.0;
    appendf(buf, bufsize, &off, "<section><div id='mem'>Mem: <span class='metric'>%s</span> / %s</div>", mem_used, mem_total);
    appendf(buf, bufsize, &off, "<div class='bar'><div class='fill mem' style='width:%.1f%%'></div></div>", mem_pct);
    double swap_pct = s->mem.swap_total ? ((double)(s->mem.swap_total - s->mem.swap_free) / (double)s->mem.swap_total * 100.0) : 0.0;
    appendf(buf, bufsize, &off, "<div id='swap'>Swap: <span class='metric'>%s</span> / %s</div>", swap_used, swap_total);
    appendf(buf, bufsize, &off, "<div class='bar'><div class='fill swap' style='width:%.1f%%'></div></div></section>", swap_pct);
    appendf(buf, bufsize, &off, "<section><div id='disk'>Disk (");
    append_html_escaped(buf, bufsize, &off, s->disk.path);
    appendf(buf, bufsize, &off, "): <span class='metric'>%s</span> / %s</div>", disk_used, disk_total);
    appendf(buf, bufsize, &off, "<div class='bar'><div class='fill disk' style='width:%.1f%%'></div></div></section>", s->disk.percent);
    appendf(buf, bufsize, &off, "<section><div>Network</div><div id='net'>%s</div><div id='net-graph' class='graph'></div></section>", net_section);
    appendf(buf, bufsize, &off, "<section><div>System</div><div id='sys'></div></section>");
    appendf(buf, bufsize, &off, "<section><small>↻ %.1fs · <span id='last-ts'>--:--:--</span></small></section>", refresh);

    appendf(buf, bufsize, &off, "<script>(function(){\n");
    appendf(buf, bufsize, &off, "const refreshMs=Math.max(250,%.0f);\n", refresh * 1000.0);
    appendf(buf, bufsize, &off, "let data=%s;\n", json_payload);
    appendf(buf, bufsize, &off, "const netWindow=300000;let netHist=[];\n");
    appendf(buf, bufsize, &off, "const metricsUrl=(function(){const path=window.location.pathname;const lastSlash=path.lastIndexOf('/');const seg=path.substring(lastSlash+1);let dir;if(path.endsWith('/')){dir=path;}else if(seg && seg.indexOf('.')>=0){dir=path.substring(0,lastSlash+1)||'/';}else{dir=path+'/';}return window.location.origin + dir + 'metrics';})();\n");
    if (token && token[0] != '\0') {
        appendf(buf, bufsize, &off, "const authToken=");
        append_json_string(buf, bufsize, &off, token);
        appendf(buf, bufsize, &off, ";\n");
    } else {
        appendf(buf, bufsize, &off, "const authToken=null;\n");
    }
    appendf(buf, bufsize, &off, "const prefersDark=(window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches);\n");
    appendf(buf, bufsize, &off, "let theme=localStorage.getItem('theme')||(prefersDark?'dark':'light');\n");
    appendf(buf, bufsize, &off, "function applyTheme(t){document.documentElement.setAttribute('data-theme',t);localStorage.setItem('theme',t);}\n");
    appendf(buf, bufsize, &off, "function clamp(v){return Math.max(0,Math.min(100,v));}\n");
    appendf(buf, bufsize, &off, "function esc(s){return String(s).replace(/[&<>\"']/g,function(c){if(c==='&')return '&amp;';if(c==='<')return '&lt;';if(c==='>')return '&gt;';if(c==='\"')return '&quot;';return '&#39;';});}\n");
    appendf(buf, bufsize, &off, "function fmtBytes(v){const u=['B','KiB','MiB','GiB','TiB'];let n=v;let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++;}return n.toFixed(1)+' '+u[i];}\n");
    appendf(buf, bufsize, &off, "function fmtUptime(sec){const s=Math.floor(sec||0);const d=Math.floor(s/86400);const h=Math.floor((s%%86400)/3600);const m=Math.floor((s%%3600)/60);if(d>0)return d+'d '+h+'h '+m+'m';if(h>0)return h+'h '+m+'m';return m+'m';}\n");
    appendf(buf, bufsize, &off, "function bar(w,c){return '<div class=\"bar\"><div class=\"fill '+c+'\" style=\"width:'+clamp(w).toFixed(1)+'%%\"></div></div>';}\n");
    appendf(buf, bufsize, &off, "function updateNetHistory(d){const t=Date.now();let rx=0,tx=0;const net=d.net||{};Object.keys(net).forEach(function(k){const r=net[k]||{};rx+=(r.rx_rate||0);tx+=(r.tx_rate||0);});netHist.push({t,rx,tx});const cutoff=t-netWindow;while(netHist.length && netHist[0].t<cutoff){netHist.shift();}if(netHist.length>600){netHist.shift();}}\n");
    appendf(buf, bufsize, &off, "function renderNetGraph(){const el=document.getElementById('net-graph');if(!el)return;if(netHist.length<2){el.innerHTML='<p class=\"muted\">Collecting network data...</p>';return;}const max=Math.max.apply(null,netHist.map(function(p){return Math.max(p.rx,p.tx,1);}));const w=300,h=80;function toPts(arr){return arr.map(function(v,i){const x=(i/(arr.length-1))*w;const y=h-(v/max*h);return x.toFixed(1)+','+y.toFixed(1);}).join(' ');}const rxPts=toPts(netHist.map(function(p){return p.rx;}));const txPts=toPts(netHist.map(function(p){return p.tx;}));el.innerHTML='<svg viewBox=\"0 0 '+w+' '+h+'\" preserveAspectRatio=\"none\"><polyline fill=\"none\" stroke=\"var(--accent-rx)\" stroke-width=\"1.4\" stroke-linecap=\"round\" stroke-linejoin=\"round\" points=\"'+rxPts+'\"/><polyline fill=\"none\" stroke=\"var(--accent-tx)\" stroke-width=\"1.4\" stroke-linecap=\"round\" stroke-linejoin=\"round\" points=\"'+txPts+'\"/></svg>';}\n");
    appendf(buf, bufsize, &off, "function render(d){if(!d)return;const up=document.getElementById('uptime-pill');if(up){up.textContent='⏱ '+fmtUptime(d.uptime_seconds);}const usr=document.getElementById('users-pill');if(usr){usr.textContent='👥 '+(d.user_count||0);}const cpu=document.getElementById('cpu');if(cpu){cpu.innerHTML='CPU: <span class=\"metric\">'+d.cpu_percent.toFixed(1)+'%%</span> | Load: '+d.loadavg.map(function(x){return x.toFixed(2);}).join(' / ');const b=cpu.nextElementSibling;if(b){b.innerHTML=bar(d.cpu_percent,'cpu');}}const coresWrap=document.getElementById('cores');if(coresWrap){const cores=d.cores||[];if(cores.length===0){coresWrap.innerHTML='<p id=\"cores-empty\">Per-core data unavailable.</p>'; }else{const rows=cores.map(function(v,i){return '<div class=\"core-row\"><span class=\"core-name\">CPU'+i+'</span><div class=\"core-bar\"><div class=\"fill cpu\" style=\"width:'+clamp(v).toFixed(1)+'%%\"></div></div><span class=\"core-pct\">'+v.toFixed(1)+'%%</span></div>';}).join('');coresWrap.innerHTML=rows;}}const usedMem=d.memory.total-d.memory.available;const mem=document.getElementById('mem');if(mem){const pct=d.memory.total?(usedMem/d.memory.total*100):0;mem.innerHTML='Mem: <span class=\"metric\">'+fmtBytes(usedMem)+'</span> / '+fmtBytes(d.memory.total);const b=mem.nextElementSibling;if(b){b.innerHTML=bar(pct,'mem');}}const sw=document.getElementById('swap');if(sw){const used=d.memory.swap_total-d.memory.swap_free;const pct=d.memory.swap_total?(used/d.memory.swap_total*100):0;sw.innerHTML='Swap: <span class=\"metric\">'+fmtBytes(used)+'</span> / '+fmtBytes(d.memory.swap_total);const b=sw.nextElementSibling;if(b){b.innerHTML=bar(pct,'swap');}}const disk=document.getElementById('disk');if(disk){const pct=d.disk.total?(d.disk.used/d.disk.total*100):0;disk.innerHTML='Disk ('+esc(d.disk.path)+'): <span class=\"metric\">'+fmtBytes(d.disk.used)+'</span> / '+fmtBytes(d.disk.total);const b=disk.nextElementSibling;if(b){b.innerHTML=bar(pct,'disk');}}const netWrap=document.getElementById('net');if(netWrap){const keys=Object.keys(d.net||{});if(keys.length===0){netWrap.innerHTML='<p id=\"net-empty\">No network traffic detected.</p>'; }else{let max=1;keys.forEach(function(k){const r=d.net[k];max=Math.max(max,r.rx_rate,r.tx_rate);});const rows=keys.sort().map(function(k){const r=d.net[k];const rxPct=r.rx_rate/max*100;const txPct=r.tx_rate/max*100;return '<tr><td>'+esc(k)+'</td><td>'+fmtBytes(r.rx_rate)+'/s'+bar(rxPct,'net-rx')+'</td><td>'+fmtBytes(r.tx_rate)+'/s'+bar(txPct,'net-tx')+'</td></tr>';}).join('');netWrap.innerHTML='<table id=\"net-table\"><tr><th>Interface</th><th>RX</th><th>TX</th></tr>'+rows+'</table>';}}updateNetHistory(d);renderNetGraph();const sys=document.getElementById('sys');if(sys){let rows=[];if(d.hostname){rows.push('<div>🏷️ '+esc(d.hostname)+'</div>');}if(typeof d.temp_c==='number'){rows.push('<div>🌡️ '+d.temp_c.toFixed(1)+'°C</div>');}if(typeof d.entropy==='number'){rows.push('<div>🎲 Entropy '+d.entropy+'</div>');}if(d.files&&typeof d.files.used==='number'&&typeof d.files.max==='number'&&d.files.max>0){const pct=d.files.used/d.files.max*100;rows.push('<div>📂 FDs '+d.files.used+'/'+d.files.max+' ('+pct.toFixed(1)+'%%)</div>');}if(rows.length===0){rows.push('<div class=\"muted\">No extra system data.</div>');}sys.innerHTML=rows.join('');}const procWrap=document.getElementById('procs');if(procWrap){const procs=d.procs||[];if(procs.length===0){procWrap.innerHTML='<p id=\"procs-empty\">No processes above 1%% CPU.</p>'; }else{const rows=procs.map(function(p){return '<tr><td>'+esc(p.name)+'</td><td>'+p.pid+'</td><td>'+p.percent.toFixed(1)+'%%</td></tr>';}).join('');procWrap.innerHTML='<table id=\"procs-table\"><tr><th>Name</th><th>PID</th><th>CPU</th></tr>'+rows+'</table>';}}const ts=document.getElementById('last-ts');if(ts){ts.textContent=new Date().toLocaleTimeString();}}\n");
    appendf(buf, bufsize, &off, "function bindTheme(){applyTheme(theme);}\n");
    appendf(buf, bufsize, &off, "async function tick(){try{const opts={cache:'no-store'};if(authToken){opts.headers={'X-WebMon-Token':authToken};}const res=await fetch(metricsUrl,opts);if(res.ok){data=await res.json();}else{console.error('poll status',res.status);}}catch(e){console.error('poll failed',e);}render(data);setTimeout(tick,refreshMs);}\n");
    appendf(buf, bufsize, &off, "bindTheme();render(data);tick();\n");
    appendf(buf, bufsize, &off, "})();</script></body></html>");
    free(json_body);
}

static void handle_http_client(int client_fd, struct SharedState *state, double refresh, const char *token) {
    char req[2048];
    ssize_t n = recv_request(client_fd, req, sizeof req);
    if (n <= 0) return;
    char method[8] = {0}, path[256] = {0};
    if (sscanf(req, "%7s %255s", method, path) != 2) {
        const char *resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nMalformed request.\n";
        write_all(client_fd, resp, strlen(resp));
        return;
    }
    if (strcmp(method, "GET") != 0) {
        const char *resp = "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/plain\r\n\r\nMethod not allowed.\n";
        write_all(client_fd, resp, strlen(resp));
        return;
    }
    if (!is_authorized(req, path, token)) {
        const char *resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\n\r\nUnauthorized.\n";
        write_all(client_fd, resp, strlen(resp));
        return;
    }

    pthread_mutex_lock(&state->lock);
    int ready = state->has_stats;
    struct Stats snapshot = state->stats;
    pthread_mutex_unlock(&state->lock);

    if (!ready) {
        const char *resp = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\n\r\nWaiting for first sample...\n";
        write_all(client_fd, resp, strlen(resp));
        return;
    }

    if (is_metrics_path(path)) {
        size_t body_size = 65536;
        char *body = malloc(body_size);
        if (!body) {
            const char *resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nOut of memory.\n";
            write_all(client_fd, resp, strlen(resp));
            return;
        }
        render_json(&snapshot, body, body_size);
        char header[128];
        snprintf(header, sizeof header,
                 "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n",
                 strlen(body));
        write_all(client_fd, header, strlen(header));
        write_all(client_fd, body, strlen(body));
        free(body);
    } else {
        size_t body_size = 131072;
        char *body = malloc(body_size);
        if (!body) {
            const char *resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nOut of memory.\n";
            write_all(client_fd, resp, strlen(resp));
            return;
        }
        render_html(&snapshot, refresh, body, body_size, token);
        char header[128];
        snprintf(header, sizeof header,
                 "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %zu\r\n\r\n",
                 strlen(body));
        write_all(client_fd, header, strlen(header));
        write_all(client_fd, body, strlen(body));
        free(body);
    }
}

static int run_http_server(const char *host, int port, double refresh, int workers, const char *token, struct SamplerArgs *sampler_cfg) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (strcmp(host, "0.0.0.0") == 0) {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid host: %s\n", host);
        close(server_fd);
        return 1;
    }

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }
    if (listen(server_fd, 8) != 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    struct SharedState state = {0};
    pthread_mutex_init(&state.lock, NULL);
    sampler_cfg->state = &state;

    pthread_t thread;
    if (pthread_create(&thread, NULL, sampler_thread, sampler_cfg) != 0) {
        perror("pthread_create");
        close(server_fd);
        return 1;
    }

    struct ClientQueue queue;
    queue_init(&queue);

    if (workers < 1) workers = 1;
    if (workers > 8) workers = 8;
    pthread_t *worker_threads = calloc((size_t)workers, sizeof(*worker_threads));
    struct WorkerArgs *worker_args = calloc((size_t)workers, sizeof(*worker_args));
    if (!worker_threads || !worker_args) {
        fprintf(stderr, "Failed to allocate worker pool.\n");
        free(worker_threads);
        free(worker_args);
        queue_stop(&queue);
        queue_destroy(&queue);
        g_stop = 1;
        pthread_join(thread, NULL);
        pthread_mutex_destroy(&state.lock);
        close(server_fd);
        return 1;
    }
    for (int i = 0; i < workers; i++) {
        worker_args[i].queue = &queue;
        worker_args[i].state = &state;
        worker_args[i].refresh = refresh;
        worker_args[i].token = token;
        if (pthread_create(&worker_threads[i], NULL, worker_thread, &worker_args[i]) != 0) {
            fprintf(stderr, "Failed to start worker %d.\n", i);
            g_stop = 1;
            workers = i;
            break;
        }
    }

    printf("Web UI ready at http://%s:%d (refresh %.1fs, workers %d). Press Ctrl+C to stop.\n",
           host, port, refresh, workers);
    while (!g_stop) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(server_fd, &rfds);
        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
        int ready = select(server_fd + 1, &rfds, NULL, NULL, &tv);
        if (ready <= 0) continue;

        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) continue;
        set_client_timeouts(client_fd);
        if (queue_push(&queue, client_fd) != 0) {
            const char *resp = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\n\r\nServer busy.\n";
            write_all(client_fd, resp, strlen(resp));
            close(client_fd);
        }
    }

    queue_stop(&queue);
    for (int i = 0; i < workers; i++) {
        pthread_join(worker_threads[i], NULL);
    }
    pthread_join(thread, NULL);
    pthread_mutex_destroy(&state.lock);
    queue_destroy(&queue);
    free(worker_threads);
    free(worker_args);
    close(server_fd);
    return 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [options]\n"
            "  -i <seconds>   Sampling interval (default 1.0, min 0.1)\n"
            "  -d <path>      Disk path to report (default /)\n"
            "  -H <host>      Host for web mode (default 127.0.0.1)\n"
            "  -p <port>      Port for web mode (default 61080)\n"
            "  -r <seconds>   Browser refresh interval for web UI (default 2.0)\n"
            "  -n <list>      Comma-separated interfaces to include (default: all non-loopback)\n"
            "  -w <count>     HTTP worker threads (default 2, max 8)\n"
            "  -t <token>     Shared token for HTTP auth (optional)\n"
            "  -h             Show this help\n"
            "  Config: " TOKEN_CONFIG_PATH " (token=...)\n",
            prog);
}

int main(int argc, char **argv) {
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    double interval = 1.0;
    const char *disk_path = "/";
    const char *host = "127.0.0.1";
    int port = 61080;
    double refresh = 2.0;
    const char *iface_arg = NULL;
    int workers = 2;
    const char *token = NULL;
    char token_buf[256] = {0};

    int opt;
    while ((opt = getopt(argc, argv, "i:d:H:p:r:n:w:t:h")) != -1) {
        switch (opt) {
            case 'i':
                interval = atof(optarg);
                if (interval < 0.1) interval = 0.1;
                break;
            case 'd':
                disk_path = optarg;
                break;
            case 'H':
                host = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'r':
                refresh = atof(optarg);
                break;
            case 'n':
                iface_arg = optarg;
                break;
            case 'w':
                workers = atoi(optarg);
                break;
            case 't':
                snprintf(token_buf, sizeof token_buf, "%s", optarg);
                token = token_buf;
                break;
            case 'h':
            default:
                usage(argv[0]);
                return (opt == 'h') ? 0 : 1;
        }
    }

    int iface_count = 0;
    char **ifaces = split_interfaces(iface_arg, &iface_count);
    struct SamplerArgs cfg = {
        .interval = interval,
        .disk_path = disk_path,
        .filters = ifaces,
        .filter_count = iface_count,
        .state = NULL,
    };
    if (!token || token[0] == '\0') {
        if (read_token_file(TOKEN_CONFIG_PATH, token_buf, sizeof token_buf) == 0) {
            token = token_buf;
        } else {
            token = NULL;
        }
    }
    int rc = run_http_server(host, port, refresh, workers, token, &cfg);
    free_interfaces(ifaces, iface_count);
    return rc;
}
