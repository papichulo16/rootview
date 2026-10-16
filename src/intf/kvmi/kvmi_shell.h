#ifndef ROOTVIEW_KVMI_SHELL_H
#define ROOTVIEW_KVMI_SHELL_H

#include "vmi/vmi_types.h"

/* interactive REPL over an already-attached session - combines the vmi
 * introspection commands and the hook commands onto the one kvmi
 * attachment, since KVMI only allows a single client attached to a vm's
 * introspection socket at a time (you used to have to quit `rv vmi` and
 * re-attach through `rv hook`, or vice versa, to get the other command
 * set). blocks until the user types "quit"/"exit" or sends EOF. */
void kvmi_shell_run(vmi_session_t *session);

#endif
