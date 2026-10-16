#ifndef ROOTVIEW_BIND_RV_H
#define ROOTVIEW_BIND_RV_H

#include <stddef.h>
#include <stdint.h>

#define RV_ERR_MAX 512
#define RV_NAME_MAX 64
#define RV_PATH_MAX 4096

typedef struct rv_handle rv_handle_t;

void rv_set_base(const char *dir);

rv_handle_t *rv_attach(const char *vm_name, char *err, size_t err_len);
void rv_detach(rv_handle_t *h);

int rv_prof(rv_handle_t *h, char *err, size_t err_len);
int rv_profiled(const rv_handle_t *h);

#endif
