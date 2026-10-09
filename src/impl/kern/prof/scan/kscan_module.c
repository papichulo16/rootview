#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "kscan_priv.h"

/* the module cross-view: four ways to reach a struct module.
 *
 *   MOD_LIST    the modules list: what lsmod and /proc/modules show
 *   MOD_TREE    mod_tree.root.tree[0]: the latch tree address lookups use
 *               (oopses, kallsyms, __module_address), one node per memory
 *               region, each naming its module
 *   MOD_TREE_1  tree[1], the latch's second copy of the same nodes
 *   MOD_CARVE   every page mapped in the module area, searched for a struct
 *               module: mkobj.mod pointing back at the struct, a known
 *               state, a printable name and list pointers that are kernel
 *               addresses or what list_del leaves. finds a module unlinked
 *               from everything, but a match is only ever added, never
 *               required, since nothing says every struct module is live.
 *
 * per module the text range is then checked against mod->kallsyms: a module
 * whose text no symbol of its own falls in has stripped itself out of
 * /proc/kallsyms. */

/* x86_64: modules map between the end of the kernel image mapping (1GiB
 * under KASLR, 512MiB without) and the fixmap */
#define MODULES_LOW 0xffffffffa0000000ull
#define MODULES_END 0xffffffffff000000ull
#define CARVE_MAX_PAGES (1u << 18) /* 1GiB of 4KiB pages */
#define KALLSYMS_MAX (1u << 18)

/* what list_del leaves, ILLEGAL_POINTER_VALUE 0xdead000000000000 */
#define LIST_POISON1 0xdead000000000100ull
#define LIST_POISON2 0xdead000000000122ull

#define MODULE_STATE_MAX 3 /* MODULE_STATE_UNFORMED */

typedef struct {
    uint64_t size; /* sizeof(struct module) */
    uint64_t list, name, name_len, state, mkobj_mod, kallsyms;
    uint64_t text_base, text_size; /* core_layout.{base,text_size} or mem[MOD_TEXT].{base,size} */
    uint64_t tree;                 /* mod_tree_root.root.tree */
    uint64_t rb_size;              /* sizeof(struct rb_node) */
    uint64_t node_to_mod;          /* mod_tree_node.node - mod_tree_node.mod */
    uint64_t ks_symtab, ks_num;    /* mod_kallsyms */
} moff_t;

static int resolve(const kwalk_t *w, moff_t *o, char *err, size_t err_len) {
    const btf_t *b = &w->kp->btf;
    kfield_t name, state;
    uint64_t mtn_mod, mtn_node;
    int64_t sz = btf_size(b, btf_find(b, "module", BTF_KIND_STRUCT));
    int64_t rb = btf_size(b, btf_find(b, "rb_node", BTF_KIND_STRUCT));
    if (sz <= 0 || (uint64_t) sz > KWALK_MAX_STRUCT) FAIL("struct module has no usable size");
    if (rb != 24) FAIL("struct rb_node isn't 24 bytes");
    o->size = (uint64_t) sz;
    o->rb_size = (uint64_t) rb;
    if (kscan_off(w, "module", "list", &o->list, err, err_len) != 0 ||
        kscan_off(w, "module", "mkobj.mod", &o->mkobj_mod, err, err_len) != 0 ||
        kscan_off(w, "module", "kallsyms", &o->kallsyms, err, err_len) != 0 ||
        kfield_resolve(b, "module", "name", &name, err, err_len) != 0 ||
        kfield_resolve(b, "module", "state", &state, err, err_len) != 0 ||
        kscan_off(w, "mod_tree_node", "mod", &mtn_mod, err, err_len) != 0 ||
        kscan_off(w, "mod_tree_node", "node", &mtn_node, err, err_len) != 0 ||
        kscan_off(w, "mod_kallsyms", "symtab", &o->ks_symtab, err, err_len) != 0 ||
        kscan_off(w, "mod_kallsyms", "num_symtab", &o->ks_num, err, err_len) != 0)
        return -1;
    if (state.size != 4) FAIL("module.state is %u bytes", state.size);
    o->name = name.offset;
    o->name_len = name.size;
    o->state = state.offset;
    o->node_to_mod = mtn_node - mtn_mod;

    /* 6.4 split the layouts into mem[MOD_MEM_NUM_TYPES] */
    uint64_t mem, base, size;
    if (kscan_off(w, "module", "mem", &mem, NULL, 0) == 0) {
        int64_t esz = btf_size(b, btf_find(b, "module_memory", BTF_KIND_STRUCT)), text = 0;
        uint32_t en = btf_find(b, "mod_mem_type", BTF_KIND_ENUM);
        if (esz <= 0 || (en && btf_enum_value(b, en, "MOD_TEXT", &text) != 0) ||
            kscan_off(w, "module_memory", "base", &base, err, err_len) != 0 ||
            kscan_off(w, "module_memory", "size", &size, err, err_len) != 0)
            FAIL("struct module_memory isn't usable");
        o->text_base = mem + (uint64_t) text * (uint64_t) esz + base;
        o->text_size = mem + (uint64_t) text * (uint64_t) esz + size;
    } else if (kscan_off(w, "module", "core_layout.base", &o->text_base, err, err_len) != 0 ||
               kscan_off(w, "module", "core_layout.text_size", &o->text_size, err, err_len) != 0) {
        return -1;
    }
    /* the tree's offset fails on its own: without CONFIG_MODULES_TREE_LOOKUP
     * there's no tree, and only those sources go */
    if (kscan_off(w, "mod_tree_root", "root.tree", &o->tree, NULL, 0) != 0) o->tree = UINT64_MAX;
    return 0;
}

static void src_list(kwalk_t *w, kscan_result_t *r, const moff_t *o, uint64_t *buf) {
    char e[256];
    uint64_t head;
    size_t n;
    if (kscan_sym(w, "modules", &head, e, sizeof(e)) != 0 ||
        kwalk_list_off(w, head, o->list, buf, KSCAN_WALK_MAX, &n, e, sizeof(e)) != 0) {
        kscan_source_failed(r, KSCAN_SRC_MOD_LIST, e);
        return;
    }
    for (size_t i = 0; i < n; i++)
        if (!kscan_add(r, KSCAN_MODULE, buf[i], KSCAN_SRC_MOD_LIST, NULL)) {
            kscan_source_failed(r, KSCAN_SRC_MOD_LIST, "too many objects");
            return;
        }
    kscan_source_ran(r, KSCAN_SRC_MOD_LIST);
}

/* tree[idx]: each rb_node is node[idx] of a latch_tree_node inside a
 * mod_tree_node, whose mod names the module */
static void src_tree(kwalk_t *w, kscan_result_t *r, const moff_t *o, unsigned idx, uint64_t *buf) {
    unsigned src = idx ? KSCAN_SRC_MOD_TREE_1 : KSCAN_SRC_MOD_TREE;
    char e[200];
    uint64_t sym;
    size_t n;
    if (o->tree == UINT64_MAX) {
        kscan_source_failed(r, src, "no mod_tree_root.root.tree (CONFIG_MODULES_TREE_LOOKUP off?)");
        return;
    }
    if (kscan_sym(w, "mod_tree", &sym, e, sizeof(e)) != 0 ||
        kwalk_rbtree(w, sym + o->tree + idx * 8ull, buf, KSCAN_WALK_MAX, &n, e, sizeof(e)) != 0) {
        kscan_source_failed(r, src, e);
        return;
    }
    for (size_t i = 0; i < n; i++) {
        uint64_t mtn = buf[i] - idx * o->rb_size - o->node_to_mod, mod;
        if (kscan_u64(w, mtn, &mod, e, sizeof(e)) != 0) {
            kscan_source_failf(r, src, "node 0x%016" PRIx64 ": %s", buf[i], e);
            return;
        }
        if (!kwalk_kernel_va(mod)) {
            kscan_source_failf(r, src, "node 0x%016" PRIx64 " names module 0x%016" PRIx64, buf[i], mod);
            return;
        }
        kscan_object_t *m = kscan_add(r, KSCAN_MODULE, mod, src, NULL);
        if (!m) {
            kscan_source_failed(r, src, "too many objects");
            return;
        }
        /* the node is embedded in the module it names */
        if (mtn < mod || mtn >= mod + o->size) m->flags |= KSCAN_MOD_STRAY_NODE;
    }
    kscan_source_ran(r, src);
}

/* ---- carving ---- */

typedef struct {
    kwalk_t *w;
    kscan_result_t *r;
    const moff_t *o;
    unsigned char *head; /* struct module up to the end of name */
    size_t head_len;
    bool full;
    char err[200];
} carve_t;

static bool list_ptr_ok(uint64_t p, uint64_t self) {
    return p == self || p == LIST_POISON1 || p == LIST_POISON2 || kwalk_kernel_va(p);
}

/* whether a struct module plausibly starts at mod */
static bool looks_like_module(carve_t *c, uint64_t mod) {
    const moff_t *o = c->o;
    if (kwalk_read(c->w, mod, c->head, c->head_len, NULL, 0) != 0) return false;
    uint32_t state;
    uint64_t next, prev;
    memcpy(&state, c->head + o->state, 4);
    memcpy(&next, c->head + o->list, 8);
    memcpy(&prev, c->head + o->list + 8, 8);
    if (state > MODULE_STATE_MAX || !list_ptr_ok(next, mod + o->list) || !list_ptr_ok(prev, mod + o->list))
        return false;
    const unsigned char *name = c->head + o->name;
    size_t i = 0;
    for (; i < o->name_len && name[i]; i++)
        if (name[i] < 0x20 || name[i] >= 0x7f) return false;
    return i > 0 && i < o->name_len;
}

static int carve_page(uint64_t va, uint64_t pa, uint64_t size, bool nx, void *ctx) {
    (void) nx;
    carve_t *c = ctx;
    uint64_t q[512];
    for (uint64_t off = 0; off < size; off += sizeof(q)) {
        if (kmem_read_pa(&c->w->kp->target.mem, pa + off, q, sizeof(q), c->err, sizeof(c->err)) != 0) return -1;
        for (unsigned i = 0; i < 512; i++) {
            /* the qword at mod + mkobj_mod holds mod */
            uint64_t at = va + off + i * 8ull, mod = at - c->o->mkobj_mod;
            if (q[i] != mod || !looks_like_module(c, mod)) continue;
            if (!kscan_add(c->r, KSCAN_MODULE, mod, KSCAN_SRC_MOD_CARVE, NULL)) {
                c->full = true;
                return 1;
            }
        }
    }
    return 0;
}

static void src_carve(kwalk_t *w, kscan_result_t *r, const moff_t *o) {
    /* modules start past the image under KASLR's 1GiB image mapping too,
     * but never inside the image */
    uint64_t start = MODULES_LOW, end;
    char e[256];
    if (kscan_sym(w, "_end", &end, e, sizeof(e)) == 0 && end > start) start = (end + 0x1fffff) & ~0x1fffffull;
    carve_t c = {.w = w, .r = r, .o = o, .head_len = o->name + o->name_len};
    if (c.head_len < o->list + 16) c.head_len = o->list + 16;
    c.head = malloc(c.head_len);
    if (!c.head) {
        kscan_source_failed(r, KSCAN_SRC_MOD_CARVE, "out of memory");
        return;
    }
    int rc = pt_for_each_page(&w->kp->target.mem, &w->kp->root, start, MODULES_END, CARVE_MAX_PAGES, carve_page, &c,
                              c.err, sizeof(c.err));
    free(c.head);
    if (c.full) kscan_source_failed(r, KSCAN_SRC_MOD_CARVE, "too many objects");
    else if (rc != 0) kscan_source_failf(r, KSCAN_SRC_MOD_CARVE, "carving 0x%016" PRIx64 "-0x%016" PRIx64 ": %s",
                                         start, (uint64_t) MODULES_END, c.err);
    else kscan_source_ran(r, KSCAN_SRC_MOD_CARVE);
}

/* ---- per module ---- */

/* how many of mod->kallsyms fall inside [base, base + size) */
static int count_syms(kwalk_t *w, const moff_t *o, uint64_t ks, uint64_t base, uint64_t size, uint32_t *nsyms,
                      uint32_t *in_text) {
    uint64_t symtab;
    uint32_t num;
    if (!kwalk_kernel_va(ks) || kscan_u64(w, ks + o->ks_symtab, &symtab, NULL, 0) != 0 ||
        kscan_u32(w, ks + o->ks_num, &num, NULL, 0) != 0 || num > KALLSYMS_MAX ||
        (num && !kwalk_kernel_va(symtab)))
        return -1;
    *nsyms = num;
    *in_text = 0;
    /* Elf64_Sym: st_value at 8, 24 bytes each */
    uint64_t chunk[3 * 256];
    for (uint32_t i = 0; i < num; i += 256) {
        uint32_t k = num - i < 256 ? num - i : 256;
        if (kwalk_read(w, symtab + i * 24ull, chunk, k * 24ull, NULL, 0) != 0) return -1;
        for (uint32_t j = 0; j < k; j++) {
            uint64_t v = chunk[3 * j + 1];
            *in_text += v >= base && v - base < size;
        }
    }
    return 0;
}

static void decode(kwalk_t *w, kscan_result_t *r, const moff_t *o) {
    unsigned char *m = malloc(o->size);
    if (!m) return;
    for (size_t i = 0; i < r->n; i++) {
        kscan_object_t *obj = &r->objs[i];
        if (kwalk_read(w, obj->addr, m, o->size, NULL, 0) != 0) {
            obj->flags |= KSCAN_UNREADABLE;
            continue;
        }
        uint32_t state, text_size;
        uint64_t text_base, ks;
        memcpy(&state, m + o->state, 4);
        memcpy(&text_base, m + o->text_base, 8);
        memcpy(&text_size, m + o->text_size, 4);
        memcpy(&ks, m + o->kallsyms, 8);
        kscan_name(obj->name, sizeof(obj->name), m + o->name, o->name_len);
        obj->u.module.state = state;
        obj->u.module.text_base = text_base;
        obj->u.module.text_size = text_size;
        uint32_t nsyms = 0, in_text = 0;
        if (count_syms(w, o, ks, text_base, text_size, &nsyms, &in_text) != 0) {
            obj->flags |= KSCAN_MOD_BAD_KALLSYMS;
            continue;
        }
        obj->u.module.nsyms = nsyms;
        obj->u.module.nsyms_in_text = in_text;
        if (text_size && !in_text) obj->flags |= KSCAN_MOD_NO_TEXT_SYMS;
    }
    free(m);
}

int kscan_modules(kwalk_t *w, kscan_result_t *r, char *err, size_t err_len) {
    moff_t o;
    if (resolve(w, &o, err, err_len) != 0) return -1;
    if (kscan_start(r, KSCAN_MODULE, err, err_len) != 0) return -1;
    uint64_t *buf = malloc(KSCAN_WALK_MAX * sizeof(*buf));
    if (!buf) {
        kscan_free(r);
        FAIL("out of memory");
    }
    bool own;
    if (kscan_window_begin(w, &own, err, err_len) != 0) {
        free(buf);
        kscan_free(r);
        return -1;
    }
    src_list(w, r, &o, buf);
    src_tree(w, r, &o, 0, buf);
    src_tree(w, r, &o, 1, buf);
    src_carve(w, r, &o);
    decode(w, r, &o);
    free(buf);
    int rc = kscan_window_end(w, own, 0, err, err_len);
    if (rc != 0) kscan_free(r);
    return rc;
}
