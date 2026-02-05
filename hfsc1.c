#include "hfsc.h"
#include <string.h>
#include <rte_malloc.h>
#include <rte_cycles.h>

/* ================= TIME & RATE CONVERSION ================= */

static inline uint64_t hfsc_now(hfsc_scheduler_t *s) {
    return rte_get_tsc_cycles() / s->cycles_per_hfsc;
}

/* FIX:
 * Convert bytes/sec → bytes per hfsc time (fixed-point)
 */
static inline uint64_t rate_to_sm(uint64_t bps, uint64_t cycles_per_hfsc) {
    return (bps << HFSC_SCALE_BITS) / (rte_get_tsc_hz() / cycles_per_hfsc);
}

/* FIX:
 * Convert microseconds → hfsc time
 */
static inline uint64_t us_to_dx(uint64_t us, uint64_t cycles_per_hfsc) {
    uint64_t cycles = (us * rte_get_tsc_hz()) / 1000000ULL;
    return cycles / cycles_per_hfsc;
}

/* ================= CURVE MATH ================= */

static uint64_t rtsc_x2y(const hfsc_runtime_t *rt, uint64_t x) {
    if (x <= rt->x) return rt->y;

    uint64_t dx = x - rt->x;
    if (dx <= rt->dx)
        return rt->y + ((dx * rt->sm1) >> HFSC_SCALE_BITS);

    dx -= rt->dx;
    return rt->y + rt->dy + ((dx * rt->sm2) >> HFSC_SCALE_BITS);
}

static uint64_t rtsc_y2x(const hfsc_runtime_t *rt, uint64_t y) {
    if (y <= rt->y) return rt->x;

    uint64_t dy = y - rt->y;
    if (dy <= rt->dy)
        return rt->x + ((dy << HFSC_SCALE_BITS) / rt->sm1);

    dy -= rt->dy;
    return rt->x + rt->dx + ((dy << HFSC_SCALE_BITS) / rt->sm2);
}

/*
 * FIX:
 * Correct min-plus convolution (no double scaling, no sign errors)
 */
static void rtsc_min(hfsc_runtime_t *rt,
                     uint64_t x,
                     uint64_t y,
                     uint64_t sm1,
                     uint64_t sm2,
                     uint64_t dx)
{
    uint64_t y1 = rtsc_x2y(rt, x);
    uint64_t dy = (dx * sm1) >> HFSC_SCALE_BITS;

    /* Convex */
    if (sm1 <= sm2) {
        if (y1 < y) return;
        goto replace;
    }

    /* Concave */
    uint64_t y2 = rtsc_x2y(rt, x + dx);
    if (y2 <= y + dy) goto replace;

    /* Intersection */
    uint64_t diff = y1 - y;
    uint64_t dsm = sm1 - sm2;
    uint64_t new_dx = (diff << HFSC_SCALE_BITS) / dsm;
    if (new_dx > dx) new_dx = dx;

    rt->x = x;
    rt->y = y;
    rt->sm1 = sm1;
    rt->sm2 = sm2;
    rt->dx = new_dx;
    rt->dy = (new_dx * sm1) >> HFSC_SCALE_BITS;
    return;

replace:
    rt->x = x;
    rt->y = y;
    rt->sm1 = sm1;
    rt->sm2 = sm2;
    rt->dx = dx;
    rt->dy = dy;
}

/* ================= CLASS ACTIVATION ================= */

static void init_runtime_curve(hfsc_runtime_t *rt,
                               hfsc_curve_t *sc,
                               hfsc_scheduler_t *s,
                               uint64_t now,
                               uint64_t bytes)
{
    rt->x = now;
    rt->y = bytes;
    rt->sm1 = rate_to_sm(sc->m1_bps, s->cycles_per_hfsc); // FIX
    rt->sm2 = rate_to_sm(sc->m2_bps, s->cycles_per_hfsc); // FIX
    rt->dx  = us_to_dx(sc->d_us, s->cycles_per_hfsc);     // FIX
    rt->dy  = (rt->dx * rt->sm1) >> HFSC_SCALE_BITS;
}

/* ================= SELECTION ================= */

static hfsc_class_t* select_rt(hfsc_class_t *cl, uint64_t now) {
    if (!cl->flags.active) return NULL;

    if (cl->is_leaf && cl->flags.eligible && cl->cl_d <= now)
        return cl;

    hfsc_class_t *best = NULL;
    uint64_t best_d = UINT64_MAX;

    for (int i = 0; i < cl->num_children; i++) {
        hfsc_class_t *c = select_rt(cl->children[i], now);
        if (c && c->cl_d < best_d) {
            best = c;
            best_d = c->cl_d;
        }
    }
    return best;
}

static hfsc_class_t* select_ls(hfsc_class_t *cl, uint64_t now) {
    if (!cl->flags.active || cl->cl_f > now) return NULL;

    if (cl->is_leaf) return cl;

    hfsc_class_t *best = NULL;
    uint64_t best_f = UINT64_MAX;

    for (int i = 0; i < cl->num_children; i++) {
        hfsc_class_t *c = select_ls(cl->children[i], now);
        if (c && c->cl_f < best_f) {
            best = c;
            best_f = c->cl_f;
        }
    }
    return best;
}

/* ================= API ================= */

int hfsc_init(hfsc_scheduler_t *s, uint64_t link_rate_bps) {
    memset(s, 0, sizeof(*s));
    s->cycles_per_hfsc = rte_get_tsc_hz() / HFSC_ONE_SEC_FP;
    if (!s->cycles_per_hfsc) s->cycles_per_hfsc = 1;
    rte_spinlock_init(&s->lock);
    return 0;
}

hfsc_class_t* hfsc_schedule(hfsc_scheduler_t *s) {
    rte_spinlock_lock(&s->lock);
    s->now = hfsc_now(s);

    hfsc_class_t *c = select_rt(s->root, s->now);
    if (!c) c = select_ls(s->root, s->now);

    rte_spinlock_unlock(&s->lock);
    return c;
}

void hfsc_update(hfsc_scheduler_t *s, hfsc_class_t *cl, uint32_t len) {
    rte_spinlock_lock(&s->lock);
    uint64_t now = hfsc_now(s);

    cl->cumul_all += len;
    cl->cumul_rt  += len;

    rtsc_min(&cl->rt, now, cl->cumul_rt,
             cl->rt.sm1, cl->rt.sm2, cl->rt.dx);

    cl->cl_d = rtsc_y2x(&cl->rt, cl->cumul_rt + len);
    cl->cl_e = rtsc_y2x(&cl->el, cl->cumul_rt);
    cl->flags.eligible = (now >= cl->cl_e);

    rtsc_min(&cl->ls, now, cl->cumul_all,
             cl->ls.sm1, cl->ls.sm2, cl->ls.dx);

    cl->cl_vt = rtsc_y2x(&cl->ls, cl->cumul_all);

    cl->last_service = now;
    rte_spinlock_unlock(&s->lock);
}
