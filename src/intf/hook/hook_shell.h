#ifndef ROOTVIEW_HOOK_SHELL_H
#define ROOTVIEW_HOOK_SHELL_H

#include "vmi/vmi_types.h"

/* interactive REPL over an already-attached session; blocks until the user
 * types "quit"/"exit" or sends EOF. */
void hook_shell_run(vmi_session_t *session);

#endif
