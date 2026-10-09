#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "kcheck_priv.h"
#include "kern/prof/kfield.h"

/* ftrace's patch sites. every function built with -mfentry starts (after
 * any endbr) with a 5-byte call to __fentry__, which the kernel rewrites
 * to a nop at boot and back into a call - to ftrace_caller, an ops'
 * trampoline or a direct target - for each function some ftrace_ops
 * attaches to. struct dyn_ftrace records each site: ip, and flags whose
 * top bits say what's attached. records live in ftrace_page blocks chained
 * from ftrace_pages_start, core kernel first, then each module's. */

#define MAX_PAGES 65536
#define MAX_RECORDS (1u << 20)

static const unsigned char NOP5[5] = {0x0f, 0x1f, 0x44, 0x00, 0x00};

/* FTRACE_FL_* from BTF's anonymous enum, by enumerator name */
typedef struct {
    uint64_t enabled, ipmodify, direct;
} fl_bits_t;

static bool fl_from_btf(const btf_t *b, fl_bits_t *fl) {
    for (uint32_t id = 1; id < b->n; id++) {
        btf_type_t t;
        int64_t en, ip, di;
        if (btf_type(b, id, &t) != 0 || (t.kind != BTF_KIND_ENUM && t.kind != BTF_KIND_ENUM64)) continue;
        if (btf_enum_value(b, id, "FTRACE_FL_ENABLED", &en) != 0) continue;
        if (btf_enum_value(b, id, "FTRACE_FL_IPMODIFY", &ip) != 0 || btf_enum_value(b, id, "FTRACE_FL_DIRECT", &di) != 0)
            return false;
        *fl = (fl_bits_t) {(uint32_t) en, (uint32_t) ip, (uint32_t) di};
        return true;
    }
    return false;
}

typedef struct {
    uint64_t next, records, index; /* ftrace_page */
    uint64_t ip, flags, size;      /* dyn_ftrace */
} layout_t;

static int layout(const kprof_t *kp, layout_t *l, char *err, size_t err_len) {
    kfield_t f;
    const char *pf[] = {"next", "records", "index"};
    uint64_t *po[] = {&l->next, &l->records, &l->index};
    for (int i = 0; i < 3; i++) {
        if (kfield_resolve(&kp->btf, "ftrace_page", pf[i], &f, err, err_len) != 0) return -1;
        *po[i] = f.offset;
    }
    if (kfield_resolve(&kp->btf, "dyn_ftrace", "ip", &f, err, err_len) != 0) return -1;
    l->ip = f.offset;
    if (kfield_resolve(&kp->btf, "dyn_ftrace", "flags", &f, err, err_len) != 0) return -1;
    l->flags = f.offset;
    int64_t sz = btf_size(&kp->btf, btf_find(&kp->btf, "dyn_ftrace", BTF_KIND_STRUCT));
    if (sz < 16 || sz > 64) FAIL("struct dyn_ftrace is %" PRId64 " bytes", sz);
    l->size = (uint64_t) sz;
    return 0;
}

/* one record: listed when it's enabled or its site isn't the nop */
static int record(kcheck_ctx_t *c, kcheck_result_t *r, const fl_bits_t *fl, uint32_t idx, uint64_t slot, uint64_t ip,
                  uint64_t flags) {
    const kprof_t *kp = c->w->kp;
    unsigned char b[5];
    uint32_t f = 0;
    uint64_t target = 0;
    bool readable = kwalk_read(c->w, ip, b, 5, NULL, 0) == 0;
    bool nop = readable && !memcmp(b, NOP5, 5);
    if (!readable) f |= KCHECK_UNREADABLE;
    else if (b[0] == 0xe8 || b[0] == 0xe9) {
        int32_t rel;
        memcpy(&rel, b + 1, 4);
        target = ip + 5 + (int64_t) rel;
        f |= KCHECK_FTRACE_CALL;
    }
    bool enabled = flags & fl->enabled;
    if (enabled) f |= KCHECK_FTRACE_ENABLED;
    if (flags & fl->ipmodify) f |= KCHECK_FTRACE_IPMODIFY;
    if (flags & fl->direct) f |= KCHECK_FTRACE_DIRECT;
    /* readable and neither the nop nor a call is a patch of its own; an
     * enabled site has to hold a call, a disabled one the nop */
    if (readable && (enabled ? !(f & KCHECK_FTRACE_CALL) : !nop)) f |= KCHECK_FTRACE_MISMATCH;
    if (!enabled && nop) return 0;
    if (!enabled && !readable) return 0; /* a site gone with freed memory: nothing attached, nothing to see */

    kcheck_entry_t *e = kcheck_add(r, idx, slot);
    if (!e) return -1;
    e->site = ip;
    const ksym_t *s = ip >= kp->img.start && ip < kp->img.end ? ksym_by_addr(&kp->ksym, ip, &e->site_off) : NULL;
    e->site_sym = s ? s->name : NULL;
    if (!s) e->site_off = 0;
    e->target = target;
    if (target) kcheck_place(c, e);
    e->flags |= f;
    e->raw = flags;
    e->suspect = (f & KCHECK_FTRACE_MISMATCH) != 0;
    r->suspect += e->suspect;
    return 0;
}

int kcheck_ftrace(kwalk_t *w, const kscan_result_t *mods, kcheck_result_t *r, char *err, size_t err_len) {
    kcheck_ctx_t c;
    if (kcheck_begin(&c, w, mods, r, KCHECK_FTRACE, err, err_len) != 0) return -1;
    const kprof_t *kp = w->kp;
    int rc = -1;
    unsigned char *recs = NULL;
    layout_t l;
    fl_bits_t fl;
    bool from_btf = fl_from_btf(&kp->btf, &fl);
    if (!from_btf) fl = (fl_bits_t) {1ull << 31, 1ull << 26, 1ull << 24}; /* the same from 5.x through 6.18 */

    const ksym_t *start = ksym_by_name(&kp->ksym, "ftrace_pages_start");
    if (!start) {
        if (err) snprintf(err, err_len, "no ftrace_pages_start symbol (CONFIG_DYNAMIC_FTRACE off?)");
        goto out;
    }
    if (layout(kp, &l, err, err_len) != 0) goto out;
    uint64_t pg;
    if (kwalk_read(w, start->addr, &pg, 8, err, err_len) != 0) goto out;

    size_t pages = 0, total = 0;
    for (; pg; pages++) {
        if (pages == MAX_PAGES) {
            if (err) snprintf(err, err_len, "more than %u ftrace pages: a cycle?", MAX_PAGES);
            goto out;
        }
        if (!kwalk_kernel_va(pg)) {
            if (err) snprintf(err, err_len, "ftrace page %zu at 0x%016" PRIx64 " isn't a kernel address", pages, pg);
            goto out;
        }
        uint64_t next, records;
        int32_t index;
        if (kwalk_read(w, pg + l.next, &next, 8, err, err_len) != 0 ||
            kwalk_read(w, pg + l.records, &records, 8, err, err_len) != 0 ||
            kwalk_read(w, pg + l.index, &index, 4, err, err_len) != 0)
            goto out;
        if (index < 0 || total + (size_t) index > MAX_RECORDS) {
            if (err) snprintf(err, err_len, "ftrace page %zu holds %d records", pages, index);
            goto out;
        }
        size_t len = (size_t) index * l.size;
        free(recs);
        if (!(recs = malloc(len ? len : 1))) {
            if (err) snprintf(err, err_len, "out of memory");
            goto out;
        }
        if (kwalk_read(w, records, recs, len, err, err_len) != 0) goto out;
        for (int32_t i = 0; i < index; i++) {
            uint64_t ip, flags;
            memcpy(&ip, recs + i * l.size + l.ip, 8);
            memcpy(&flags, recs + i * l.size + l.flags, 8);
            if (record(&c, r, &fl, (uint32_t) (total + (size_t) i), records + i * l.size, ip, flags) != 0) {
                if (err) snprintf(err, err_len, "out of memory");
                goto out;
            }
        }
        total += (size_t) index;
        pg = next;
    }
    r->checked = total;
    snprintf(r->note, sizeof(r->note), "%zu records in %zu ftrace pages%s", total, pages,
             from_btf ? "" : "; FTRACE_FL_* not in BTF, using 5.x-6.18's values");
    rc = 0;
out:
    free(recs);
    return kcheck_end(&c, r, rc, err, err_len);
}
