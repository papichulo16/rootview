#ifndef ROOTVIEW_HOOK_CLI_H
#define ROOTVIEW_HOOK_CLI_H

/* entry point for `rv hook <args>`. argv[0] is the subcommand (e.g.
 * "attach"), argv[1..] are its arguments - the caller strips "rv" and
 * "hook" first. */
int hook_cli_main(int argc, char **argv);

#endif
