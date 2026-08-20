#ifndef ROOTVIEW_VM_CLI_H
#define ROOTVIEW_VM_CLI_H

/* entry point for `rv vm <args>`. argv[0] is the subcommand (e.g. "create"),
 * argv[1..] are its arguments — the caller strips "rv" and "vm" first. */
int vm_cli_main(int argc, char **argv);

#endif
