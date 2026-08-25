#include "vm/vm_cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vm/vm.h"
#include "vm/vm_config.h"

typedef int (*vm_action_fn)(const char *name, char *err, size_t err_len);

static void print_usage(void) {
    fprintf(stderr,
            "usage: rv vm <command> [args]\n\n"
            "commands:\n"
            "  create <name> [--config <file>] [--memory <mb>] [--cpus <n>]\n"
            "                [--disk <path>] [--cdrom <path>] [--network none|user|tap]\n"
            "                [--display none|gtk|vnc] [--no-kvm] [--no-kvmi] [--extra-args \"<args>\"]\n"
            "  start <name>              boot a created vm\n"
            "  stop <name>               gracefully shut a vm down\n"
            "  restart <name>            stop then start\n"
            "  destroy <name> [--force]  delete a vm and its state\n"
            "  inspect <name>            print full vm state\n"
            "  list                      list all known vms\n"
            "  console <name>            attach to the qemu monitor\n");
}

static int require_name(int argc, char **argv, const char **name) {
    if (argc < 1) {
        fprintf(stderr, "error: missing <name>\n");
        return -1;
    }
    *name = argv[0];
    return 0;
}

static int cmd_create(int argc, char **argv) {
    const char *name;
    if (require_name(argc, argv, &name) != 0) return 1;

    vm_config_t cfg;
    vm_config_default(&cfg, name);

    for (int i = 1; i < argc; i++) {
        char err[256];
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            if (vm_config_from_json_file(argv[++i], &cfg, err, sizeof(err)) != 0) {
                fprintf(stderr, "error: %s\n", err);
                return 1;
            }
        } else if (strcmp(argv[i], "--memory") == 0 && i + 1 < argc) {
            cfg.memory_mb = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--cpus") == 0 && i + 1 < argc) {
            cfg.cpus = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--disk") == 0 && i + 1 < argc) {
            snprintf(cfg.disk_image, sizeof(cfg.disk_image), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--cdrom") == 0 && i + 1 < argc) {
            snprintf(cfg.cdrom, sizeof(cfg.cdrom), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--network") == 0 && i + 1 < argc) {
            cfg.network = vm_net_mode_parse(argv[++i]);
        } else if (strcmp(argv[i], "--display") == 0 && i + 1 < argc) {
            cfg.display = vm_display_mode_parse(argv[++i]);
        } else if (strcmp(argv[i], "--no-kvm") == 0) {
            cfg.use_kvm = false;
        } else if (strcmp(argv[i], "--no-kvmi") == 0) {
            cfg.kvmi_enabled = false;
        } else if (strcmp(argv[i], "--extra-args") == 0 && i + 1 < argc) {
            snprintf(cfg.extra_args, sizeof(cfg.extra_args), "%s", argv[++i]);
        } else {
            fprintf(stderr, "error: unknown or incomplete flag '%s'\n", argv[i]);
            return 1;
        }
    }

    /* --config may carry its own "name"; the positional arg always wins */
    snprintf(cfg.name, sizeof(cfg.name), "%s", name);

    char err[256];
    if (vm_create(&cfg, err, sizeof(err)) != 0) {
        fprintf(stderr, "error: %s\n", err);
        return 1;
    }
    printf("created vm '%s'\n", name);
    return 0;
}

static int cmd_action(int argc, char **argv, vm_action_fn fn, const char *verb) {
    const char *name;
    if (require_name(argc, argv, &name) != 0) return 1;

    char err[256];
    if (fn(name, err, sizeof(err)) != 0) {
        fprintf(stderr, "error: %s\n", err);
        return 1;
    }
    printf("%s '%s'\n", verb, name);
    return 0;
}

static int cmd_destroy(int argc, char **argv) {
    const char *name;
    if (require_name(argc, argv, &name) != 0) return 1;

    bool force = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--force") == 0) force = true;
    }

    char err[256];
    if (vm_destroy(name, force, err, sizeof(err)) != 0) {
        fprintf(stderr, "error: %s\n", err);
        return 1;
    }
    printf("destroyed '%s'\n", name);
    return 0;
}

static int cmd_inspect(int argc, char **argv) {
    const char *name;
    if (require_name(argc, argv, &name) != 0) return 1;
    vm_inspect(name);
    return 0;
}

static int cmd_console(int argc, char **argv) {
    const char *name;
    if (require_name(argc, argv, &name) != 0) return 1;

    char err[256];
    if (vm_console(name, err, sizeof(err)) != 0) {
        fprintf(stderr, "error: %s\n", err);
        return 1;
    }
    return 0;
}

int vm_cli_main(int argc, char **argv) {
    if (argc < 1) {
        print_usage();
        return 1;
    }

    const char *cmd = argv[0];
    argc--;
    argv++;

    if (strcmp(cmd, "create") == 0) return cmd_create(argc, argv);
    if (strcmp(cmd, "start") == 0) return cmd_action(argc, argv, vm_start, "started");
    if (strcmp(cmd, "stop") == 0) return cmd_action(argc, argv, vm_stop, "stopped");
    if (strcmp(cmd, "restart") == 0) return cmd_action(argc, argv, vm_restart, "restarted");
    if (strcmp(cmd, "destroy") == 0) return cmd_destroy(argc, argv);
    if (strcmp(cmd, "inspect") == 0) return cmd_inspect(argc, argv);
    if (strcmp(cmd, "console") == 0) return cmd_console(argc, argv);
    if (strcmp(cmd, "list") == 0) {
        vm_list();
        return 0;
    }
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        print_usage();
        return 0;
    }

    fprintf(stderr, "error: unknown command '%s'\n\n", cmd);
    print_usage();
    return 1;
}
