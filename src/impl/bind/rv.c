#include "rv_priv.h"

#include <stdio.h>
#include <stdlib.h>

#include "vm/vm_store.h"

void rv_set_err(char *err, size_t err_len, const char *msg) {
    if (err && err_len) snprintf(err, err_len, "%s", msg);
}

int rv_need_prof(const rv_handle_t *h, char *err, size_t err_len) {
    if (h->prof) return 0;
    rv_set_err(err, err_len, "no kernel profile (rv_prof)");
    return -1;
}

void rv_prof_free(rv_handle_t *h) {
    if (!h->prof) return;
    if (h->w.in_window) kwalk_end(&h->w, NULL, 0);
    kwalk_free(&h->w);
    kprof_free(&h->kp);
    h->prof = false;
}

API void rv_set_base(const char *dir) {
    vm_store_set_base(dir);
}

API rv_handle_t *rv_attach(const char *vm_name, char *err, size_t err_len) {
    rv_handle_t *h = calloc(1, sizeof(*h));
    if (!h) {
        rv_set_err(err, err_len, "out of memory");
        return NULL;
    }
    if (vmi_attach(vm_name, &h->session, err, err_len) != 0) {
        free(h);
        return NULL;
    }
    hook_manager_init(&h->hooks, &h->session);
    return h;
}

API void rv_detach(rv_handle_t *h) {
    if (!h) return;
    hook_manager_clear(&h->hooks);
    rv_prof_free(h);
    vmi_detach(&h->session);
    free(h);
}

API int rv_prof(rv_handle_t *h, char *err, size_t err_len) {
    rv_prof_free(h);
    if (kprof_init(&h->kp, &h->session, err, err_len) != 0) return -1;
    kwalk_init(&h->w, &h->kp, 0);
    h->prof = true;
    return 0;
}

API int rv_profiled(const rv_handle_t *h) {
    return h->prof;
}
