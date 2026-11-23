#ifndef ROOTVIEW_PKVMI_ADB_H
#define ROOTVIEW_PKVMI_ADB_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* the pkvmi CLI (pkvmi-mod's userspace, talking to /dev/pkvmi) running on
 * the phone as root, driven over `adb shell`. commands are pipelined: the
 * CLI answers in order, one prompt per command, so many can be in flight. */

#define PKVMI_ADB_CLI_PATH "/data/local/tmp/pkvmi"
#define PKVMI_ADB_PAGE 4096ull
#define PKVMI_ADB_REG_NAME_MAX 32

typedef struct {
    pid_t pid;
    int fd; /* the CLI's stdin and stdout */
    char *buf;
    size_t len, cap;
} pkvmi_adb_t;

typedef struct {
    char name[PKVMI_ADB_REG_NAME_MAX];
    uint64_t value;
} pkvmi_adb_reg_t;

/* serial picks the device ("" for adb's default). adb has to be on PATH;
 * ADB_SERVER_SOCKET reaches a server on another machine. */
int pkvmi_adb_open(pkvmi_adb_t *adb, const char *serial, char *err, size_t err_len);
void pkvmi_adb_close(pkvmi_adb_t *adb);

/* n physical pages, each read through readpa_el1, into out (n * PAGE bytes).
 * pas have to be page-aligned. */
int pkvmi_adb_read_pages(pkvmi_adb_t *adb, const uint64_t *pas, size_t n, unsigned char *out, char *err,
                         size_t err_len);

/* "regdump_el1" or "regdump": every "name value" line it prints */
int pkvmi_adb_regdump(pkvmi_adb_t *adb, const char *cmd, pkvmi_adb_reg_t *regs, size_t max, size_t *n, char *err,
                      size_t err_len);

#endif
