#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#include "vm/vm.h"
#include "vm/vm_config.h"
#include "vm/vm_state.h"
#include "vm/vm_types.h"

static int checks_run = 0;
static int checks_failed = 0;

static void check(bool cond, const char *what) {
    checks_run++;
    if (cond) {
        printf("  [PASS] %s\n", what);
    } else {
        checks_failed++;
        printf("  [FAIL] %s\n", what);
    }
}

static bool vm_is_alive(const char *name) {
    vm_runtime_state_t st;
    vm_state_load(name, &st);
    return vm_state_is_alive(&st);
}

int main(void) {
    const char *name = "rv-smoketest";
    char err[256];

    printf("== rootview VM subsystem smoke test ==\n\n");

    /* clean up any leftover state from a previous run */
    vm_destroy(name, true, NULL, 0);

    printf("-- create --\n");
    vm_config_t cfg;
    vm_config_default(&cfg, name);
    check(vm_create(&cfg, err, sizeof(err)) == 0, "vm_create succeeds");
    check(vm_create(&cfg, err, sizeof(err)) != 0, "vm_create rejects a duplicate name");

    printf("\n-- list --\n");
    vm_list();

    printf("\n-- inspect (stopped) --\n");
    vm_inspect(name);
    check(!vm_is_alive(name), "vm is stopped right after create");

    printf("\n-- start --\n");
    check(vm_start(name, err, sizeof(err)) == 0, "vm_start spawns qemu");
    usleep(300000);
    check(vm_is_alive(name), "vm is alive after start");
    check(vm_start(name, err, sizeof(err)) != 0, "vm_start rejects a double start");

    printf("\n-- inspect (running) --\n");
    vm_inspect(name);

    printf("\n-- stop --\n");
    check(vm_stop(name, err, sizeof(err)) == 0, "vm_stop succeeds");
    check(!vm_is_alive(name), "vm is stopped after stop");
    check(vm_stop(name, err, sizeof(err)) != 0, "vm_stop rejects a vm that isn't running");

    printf("\n-- restart --\n");
    check(vm_restart(name, err, sizeof(err)) == 0, "vm_restart succeeds from stopped");
    usleep(300000);
    check(vm_is_alive(name), "vm is alive after restart");

    printf("\n-- destroy --\n");
    check(vm_destroy(name, false, err, sizeof(err)) != 0, "vm_destroy without --force rejects a running vm");
    check(vm_destroy(name, true, err, sizeof(err)) == 0, "vm_destroy --force stops and removes the vm");
    check(vm_destroy(name, true, err, sizeof(err)) != 0, "vm_destroy on a missing vm fails");

    printf("\n== %d/%d checks passed ==\n", checks_run - checks_failed, checks_run);
    return checks_failed == 0 ? 0 : 1;
}
