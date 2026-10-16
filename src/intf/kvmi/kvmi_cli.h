#ifndef ROOTVIEW_KVMI_CLI_H
#define ROOTVIEW_KVMI_CLI_H

/* entry point for `rv kvmi <args>` - argv[0] is the subcommand (e.g.
 * "attach"), argv[1..] are its arguments - the caller strips "rv" and
 * "kvmi" first. */
int kvmi_cli_main(int argc, char **argv);

#endif
