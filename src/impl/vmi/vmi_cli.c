#include "vmi/vmi_cli.h"

#include <stdio.h>
#include <string.h>

#include "vmi/vmi.h"
#include "vmi/vmi_shell.h"

static void print_usage(void) {
    fprintf(stderr,
            "usage: rv vmi <command> [args]\n\n"
            "commands:\n"
            "  attach <name>   attach to a running vm and drop into the introspection shell\n");
}

static int cmd_attach(int argc, char **argv) {
    if (argc < 1) {
        fprintf(stderr, "error: missing <name>\n");
        return 1;
    }
    const char *name = argv[0];

    vmi_session_t session = {0};
    char err[256];
    if (vmi_attach(name, &session, err, sizeof(err)) != 0) {
        fprintf(stderr, "error: %s\n", err);
        return 1;
    }

    printf("attached to '%s'. type 'help' for commands, 'quit' to detach.\n", name);
    vmi_shell_run(&session);
    vmi_detach(&session);
    return 0;
}

int vmi_cli_main(int argc, char **argv) {
    if (argc < 1) {
        print_usage();
        return 1;
    }

    const char *cmd = argv[0];
    argc--;
    argv++;

    if (strcmp(cmd, "attach") == 0) return cmd_attach(argc, argv);
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        print_usage();
        return 0;
    }

    fprintf(stderr, "error: unknown command '%s'\n\n", cmd);
    print_usage();
    return 1;
}
