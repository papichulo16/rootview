#ifndef ROOTVIEW_BIND_RV_PRIV_H
#define ROOTVIEW_BIND_RV_PRIV_H

#include <stdbool.h>

#include "bind/rootview.h"
#include "hook/hook.h"
#include "kern/kprof.h"
#include "kern/kwalk.h"
#include "vmi/vmi.h"

#define API __attribute__((visibility("default")))

struct rv_handle {
    vmi_session_t session;
    hook_manager_t hooks;

    bool prof;
    kprof_t kp;
    kwalk_t w;
    rv_event_t events[RV_EVENTS_MAX];
    size_t head, count;
    uint64_t seq, dropped;
};

void rv_set_err(char *err, size_t err_len, const char *msg);

int rv_need_prof(const rv_handle_t *h, char *err, size_t err_len);

void rv_prof_free(rv_handle_t *h);

#endif
