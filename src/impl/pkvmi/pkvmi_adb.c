#define _GNU_SOURCE /* memmem */
#include "pkvmi/pkvmi_adb.h"

#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define PROMPT "pkvmi> "
#define PROMPT_LEN (sizeof(PROMPT) - 1)
#define ROWS (PKVMI_ADB_PAGE / 16)
#define TIMEOUT_MS 20000
/* commands in flight: a few KiB of stdin, well under the socket buffer */
#define WINDOW 128
#define CMD_MAX 64

static void adb_exec(int fd, const char *serial) {
    const char *argv[9];
    int i = 0;

    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    argv[i++] = "adb";
    if (serial[0]) {
        argv[i++] = "-s";
        argv[i++] = serial;
    }
    argv[i++] = "shell";
    argv[i++] = "su";
    argv[i++] = "-c";
    argv[i++] = PKVMI_ADB_CLI_PATH;
    argv[i] = NULL;
    execvp("adb", (char *const *) argv);
    _exit(127);
}

/* the reply to the oldest command still in flight, NUL-terminated in place of
 * its prompt. *next is where the reply after it starts. */
static int adb_reply(pkvmi_adb_t *adb, size_t from, char **reply, size_t *next, char *err, size_t err_len) {
    int rc = -1;
    char *hit;

    while (!(hit = adb->len > from ? memmem(adb->buf + from, adb->len - from, PROMPT, PROMPT_LEN) : NULL)) {
        struct pollfd p = {.fd = adb->fd, .events = POLLIN};
        ssize_t got;

        if (adb->cap - adb->len < 65536) {
            size_t cap = adb->cap * 2 + 65536;
            char *grown = realloc(adb->buf, cap);
            if (!grown) {
                if (err) snprintf(err, err_len, "out of memory");
                goto out;
            }
            adb->buf = grown;
            adb->cap = cap;
        }
        if (poll(&p, 1, TIMEOUT_MS) <= 0) {
            if (err) snprintf(err, err_len, "the phone's pkvmi CLI stopped answering");
            goto out;
        }
        got = read(adb->fd, adb->buf + adb->len, adb->cap - adb->len - 1);
        if (got <= 0) {
            adb->buf[adb->len] = '\0';
            if (err) snprintf(err, err_len, "pkvmi CLI exited: %.200s", adb->buf + from);
            goto out;
        }
        adb->len += (size_t) got;
    }
    *hit = '\0';
    *reply = adb->buf + from;
    *next = (size_t) (hit - adb->buf) + PROMPT_LEN;
    rc = 0;

out:
    return rc;
}

/* drops the replies before off once they're consumed */
static void adb_consume(pkvmi_adb_t *adb, size_t off) {
    memmove(adb->buf, adb->buf + off, adb->len - off);
    adb->len -= off;
}

static int adb_send(pkvmi_adb_t *adb, const char *cmd, char *err, size_t err_len) {
    int rc = -1;
    size_t len = strlen(cmd), sent = 0;

    while (sent < len) {
        ssize_t n = send(adb->fd, cmd + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            if (err) snprintf(err, err_len, "writing to the pkvmi CLI: %s", strerror(errno));
            goto out;
        }
        sent += (size_t) n;
    }
    rc = 0;

out:
    return rc;
}

static int adb_greeting(pkvmi_adb_t *adb, char *err, size_t err_len) {
    int rc = -1;
    char *reply;
    size_t next;

    if (adb_reply(adb, 0, &reply, &next, err, err_len) != 0) goto out;
    if (!strstr(reply, "pkvmi init:")) {
        if (err) snprintf(err, err_len, "pkvmi init failed on the phone: %.200s", reply);
        goto out;
    }
    adb_consume(adb, next);
    rc = 0;

out:
    return rc;
}

int pkvmi_adb_open(pkvmi_adb_t *adb, const char *serial, char *err, size_t err_len) {
    int rc = -1;
    int fds[2];

    *adb = (pkvmi_adb_t) {.pid = -1, .fd = -1};
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) != 0) {
        if (err) snprintf(err, err_len, "socketpair: %s", strerror(errno));
        goto out;
    }
    adb->pid = fork();
    if (adb->pid == 0) adb_exec(fds[1], serial);
    close(fds[1]);
    adb->fd = fds[0];
    if (adb->pid < 0) {
        if (err) snprintf(err, err_len, "fork: %s", strerror(errno));
        goto out;
    }
    rc = adb_greeting(adb, err, err_len);

out:
    if (rc != 0) pkvmi_adb_close(adb);
    return rc;
}

void pkvmi_adb_close(pkvmi_adb_t *adb) {
    if (adb->fd >= 0) {
        send(adb->fd, "exit\n", 5, MSG_NOSIGNAL);
        close(adb->fd);
    }
    if (adb->pid > 0) {
        kill(adb->pid, SIGTERM);
        waitpid(adb->pid, NULL, 0);
    }
    free(adb->buf);
    *adb = (pkvmi_adb_t) {.pid = -1, .fd = -1};
}

/* one hexdump reply: ROWS lines of "<addr>  <u64> <u64>" starting at pa */
static int adb_parse_page(const char *reply, uint64_t pa, unsigned char *page) {
    int rc = -1;
    const char *p = reply;

    for (size_t row = 0; row < ROWS; row++) {
        char *end;
        uint64_t addr = strtoull(p, &end, 16);
        if (end == p || addr != pa + row * 16) goto out;
        for (int col = 0; col < 2; col++) {
            p = end;
            uint64_t v = strtoull(p, &end, 16);
            if (end == p) goto out;
            memcpy(page + row * 16 + col * 8, &v, 8);
        }
        p = end;
    }
    rc = 0;

out:
    return rc;
}

int pkvmi_adb_read_pages(pkvmi_adb_t *adb, const uint64_t *pas, size_t n, unsigned char *out, char *err,
                         size_t err_len) {
    int rc = -1;
    size_t sent = 0, done = 0, off = 0;
    size_t bad = n;
    char cmd[CMD_MAX];

    while (done < n) {
        char *reply;
        size_t next;

        for (; sent < n && sent - done < WINDOW; sent++) {
            snprintf(cmd, sizeof(cmd), "readpa_el1 %" PRIx64 "\n", pas[sent]);
            if (adb_send(adb, cmd, err, err_len) != 0) goto out;
        }
        if (adb_reply(adb, off, &reply, &next, err, err_len) != 0) goto out;
        /* keep draining after a bad page so the replies stay in step */
        if (adb_parse_page(reply, pas[done], out + done * PKVMI_ADB_PAGE) != 0 && bad == n) bad = done;
        off = next;
        if (off > (1u << 20)) {
            adb_consume(adb, off);
            off = 0;
        }
        done++;
    }
    adb_consume(adb, off);
    if (bad != n) {
        if (err) snprintf(err, err_len, "the phone couldn't read physical page 0x%" PRIx64, pas[bad]);
        goto out;
    }
    rc = 0;

out:
    return rc;
}

int pkvmi_adb_regdump(pkvmi_adb_t *adb, const char *cmd, pkvmi_adb_reg_t *regs, size_t max, size_t *n, char *err,
                      size_t err_len) {
    int rc = -1;
    char line[CMD_MAX];
    char *reply, *save = NULL;
    size_t next;

    *n = 0;
    snprintf(line, sizeof(line), "%s\n", cmd);
    if (adb_send(adb, line, err, err_len) != 0) goto out;
    if (adb_reply(adb, 0, &reply, &next, err, err_len) != 0) goto out;
    for (char *l = strtok_r(reply, "\n", &save); l && *n < max; l = strtok_r(NULL, "\n", &save)) {
        pkvmi_adb_reg_t *r = &regs[*n];
        if (sscanf(l, "%31s %" SCNx64, r->name, &r->value) == 2) (*n)++;
    }
    adb_consume(adb, next);
    if (*n == 0) {
        if (err) snprintf(err, err_len, "%s printed no registers", cmd);
        goto out;
    }
    rc = 0;

out:
    return rc;
}
