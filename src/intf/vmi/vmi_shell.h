#ifndef ROOTVIEW_VMI_SHELL_H
#define ROOTVIEW_VMI_SHELL_H

#include "vmi/vmi_types.h"

/* interactive REPL over an already-attached session; blocks until the user
 * types "quit"/"exit" or sends EOF. only ever calls vmi.h functions - never
 * touches libvmi or the vm module directly, so the same commands stay valid
 * if the shell is ever replaced by a different frontend. */
void vmi_shell_run(vmi_session_t *session);

#endif
