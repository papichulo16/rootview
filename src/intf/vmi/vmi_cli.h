#ifndef ROOTVIEW_VMI_CLI_H
#define ROOTVIEW_VMI_CLI_H

/* entry point for `rv vmi <args>`. argv[0] is the subcommand (e.g. "attach"),
 * argv[1..] are its arguments — the caller strips "rv" and "vmi" first. */
int vmi_cli_main(int argc, char **argv);

#endif
