#ifndef ROOTVIEW_HOOK_SHELL_H
#define ROOTVIEW_HOOK_SHELL_H

#include "vmi/vmi_types.h"

/* interactive REPL over an already-attached session; blocks until the user
 * types "quit"/"exit" or sends EOF. only ever calls hook.h and vmi.h
 * functions. any hooks left registered when the shell exits are torn down
 * automatically. */
void hook_shell_run(vmi_session_t *session);

#endif
