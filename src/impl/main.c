#include <stdio.h>
#include <string.h>

#include "vm/vm_cli.h"
#include "vmi/vmi_cli.h"

static void print_usage(void) {
    fprintf(stderr,
            "usage: rv <module> [args]\n\n"
            "modules:\n"
            "  vm    manage qemu/kvm virtual machines\n"
            "  vmi   introspect a running vm through libvmi\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    const char *module = argv[1];

    if (strcmp(module, "vm") == 0) return vm_cli_main(argc - 2, argv + 2);
    if (strcmp(module, "vmi") == 0) return vmi_cli_main(argc - 2, argv + 2);

    if (strcmp(module, "help") == 0 || strcmp(module, "--help") == 0 || strcmp(module, "-h") == 0) {
        print_usage();
        return 0;
    }

    fprintf(stderr, "error: unknown module '%s'\n\n", module);
    print_usage();

    return 1;
}

