/********************************************************************
 * HFSC Implementation File
 ********************************************************************/

#include "hfsc.h"
#include <rte_malloc.h>
#include <rte_log.h>

#define HFSC_LOG(level, fmt, ...) \
    RTE_LOG(level, USER1, "HFSC: " fmt "\n", ##__VA_ARGS__)

/* ================= INTERNAL FUNCTIONS ================= */

static inline uint64_t now_cycles(void) {
    return rte_get_tsc_cycles();
}

static inline double cycles_to_sec(uint64_t c, uint64_t hz) {
    return (double)c / hz;
}

static inline double bps_to_bpcycle(uint64_t bps, uint64_t hz) {
    return (double)bps / hz;
}

/* Runtime curve mathematics */
static double rtsc_x2y(const hfsc_runtime_curve_t *rt, double x) {
    if (x <= rt->x) return rt->y;
    if (x <= rt->x + rt->dx)
        return rt->y + (x - rt->x) * rt->sm1;
    return rt->y + rt->dy + (x - rt->x - rt->dx) * rt->sm2;
}

static double rtsc_y2x(const hfsc_runtime_curve_t *rt, double y) {
    if (y <= rt->y) return rt->x;
    if (y <= rt->y + rt->dy)
        return rt->x + (y - rt->y) / rt->sm1;
    return rt->x + rt->dx + (y - rt->y - rt->dy) / rt->sm2;
}

static void rtsc_min(hfsc_runtime_curve_t *rt,
                     double new_x,
                     double new_y,
                     double sm1,
                     double sm2,
                     double dx) {
    double y1 = rtsc_x2y(rt, new_x);
    double dy_new = dx * sm1;

    /* Convex curve (m1 <= m2) */
    if (sm1 <= sm2 + 1e-12) {
        if (y1 < new_y) return; /* Current is better */
        rt->x = new_x;
        rt->y = new_y;
        rt->sm1 = sm1;
        rt->sm2 = sm2;
        rt->dx = dx;
        rt->dy = dy_new;
        return;
    }

    /* Concave curve (m1 > m2) */
    double y2 = rtsc_x2y(rt, new_x + dx);
    if (y2 <= new_y + dy_new) {
        rt->x = new_x;
        rt->y = new_y;
        rt->sm1 = sm1;
        rt->sm2 = sm2;
        rt->dx = dx;
        rt->dy = dy_new;
        return;
    }

    /* Intersection - find new dx */
    double diff = y1 - new_y;
    double dsm = sm1 - sm2;
    double new_dx = (dsm > 1e-12) ? diff / dsm : dx;
    double new_dy = new_dx * sm1;

    rt->x = new_x;
    rt->y = new_y;
    rt->sm1 = sm1;
    rt->sm2 = sm2;
    rt->dx = new_dx;
    rt->dy = new_dy;
}

static void rtsc_copy(hfsc_runtime_curve_t *dst, const hfsc_runtime_curve_t *src) {
    memcpy(dst, src, sizeof(*dst));
}

/* Initialize runtime curve */
static void init_runtime_curve(hfsc_runtime_curve_t *rt,
                              double now_sec,
                              double start_bytes,
                              const hfsc_service_curve_t *sc,
                              uint64_t hz) {
    double sm1 = bps_to_bpcycle(sc->m1, hz);
    double sm2 = bps_to_bpcycle(sc->m2, hz);
    double dx = (double)sc->d / 1000000.0; /* us to seconds */

    rt->x = now_sec;
    rt->y = start_bytes;
    rt->sm1 = sm1;
    rt->sm2 = sm2;
    rt->dx = dx;
    rt->dy = dx * sm1;
    rt->last_update = (uint64_t)(now_sec * hz);
}

/* Peek next packet length */
static uint32_t peek_next_len(hfsc_class_t *cls) {
    if (cls->queue_ops.peek) {
        void *pkt = cls->queue_ops.peek(cls->queue_ctx);
        if (pkt) {
            return rte_pktmbuf_pkt_len((struct rte_mbuf *)pkt);
        }
    }
    
    /* Fallback to queue peek */
    if (cls->q && !rte_ring_empty(cls->q)) {
        void *obj;
        if (rte_ring_peek(cls->q, &obj) == 0) {
            return rte_pktmbuf_pkt_len((struct rte_mbuf *)obj);
        }
    }
    
    return cls->rsc.umax ? cls->rsc.umax : HFSC_AVG_PKT_LEN;
}

/* Heap operations */
static void heap_init(hfsc_heap_t *heap, uint32_t capacity, bool is_rt) {
    heap->classes = rte_zmalloc(NULL, capacity * sizeof(hfsc_class_t*), 64);
    heap->keys = rte_zmalloc(NULL, capacity * sizeof(uint64_t), 64);
    heap->indices = rte_zmalloc(NULL, HFSC_MAX_CLASSES * sizeof(int32_t), 64);
    heap->capacity = capacity;
    heap->size = 0;
    heap->is_rt_heap = is_rt;
    
    if (heap->indices) {
        for (uint32_t i = 0; i < HFSC_MAX_CLASSES; i++) {
            heap->indices[i] = -1;
        }
    }
}

static void heap_swap(hfsc_heap_t *heap, uint32_t i, uint32_t j) {
    hfsc_class_t *tmp_cls = heap->classes[i];
    uint64_t tmp_key = heap->keys[i];
    
    heap->classes[i] = heap->classes[j];
    heap->keys[i] = heap->keys[j];
    heap->classes[j] = tmp_cls;
    heap->keys[j] = tmp_key;
    
    if (heap->indices) {
        heap->indices[heap->classes[i]->class_id] = i;
        heap->indices[heap->classes[j]->class_id] = j;
    }
    
    if (heap->is_rt_heap) {
        heap->classes[i]->rt_heap_idx = i;
        heap->classes[j]->rt_heap_idx = j;
    } else {
        heap->classes[i]->ls_heap_idx = i;
        heap->classes[j]->ls_heap_idx = j;
    }
}

static void heap_sift_up(hfsc_heap_t *heap, uint32_t idx) {
    while (idx > 0) {
        uint32_t parent = (idx - 1) >> 1;
        if (heap->keys[idx] >= heap->keys[parent])
            break;
        heap_swap(heap, idx, parent);
        idx = parent;
    }
}

static void heap_sift_down(hfsc_heap_t *heap, uint32_t idx) {
    uint32_t size = heap->size;
    
    while (1) {
        uint32_t left = (idx << 1) + 1;
        uint32_t right = left + 1;
        uint32_t smallest = idx;
        
        if (left < size && heap->keys[left] < heap->keys[smallest])
            smallest = left;
        if (right < size && heap->keys[right] < heap->keys[smallest])
            smallest = right;
        
        if (smallest == idx)
            break;
            
        heap_swap(heap, idx, smallest);
        idx = smallest;
    }
}

static void heap_push(hfsc_heap_t *heap, hfsc_class_t *cls, uint64_t key) {
    if (heap->size >= heap->capacity) {
        uint32_t new_cap = heap->capacity * 2;
        hfsc_class_t **new_classes = rte_realloc(heap->classes,
                                                new_cap * sizeof(hfsc_class_t*),
                                                64);
        uint64_t *new_keys = rte_realloc(heap->keys,
                                        new_cap * sizeof(uint64_t),
                                        64);
        if (!new_classes || !new_keys) {
            HFSC_LOG(ERR, "Heap expansion failed");
            return;
        }
        heap->classes = new_classes;
        heap->keys = new_keys;
        heap->capacity = new_cap;
    }
    
    uint32_t idx = heap->size++;
    heap->classes[idx] = cls;
    heap->keys[idx] = key;
    
    if (heap->indices) {
        heap->indices[cls->class_id] = idx;
    }
    
    heap_sift_up(heap, idx);
}

static hfsc_class_t* heap_peek(hfsc_heap_t *heap) {
    return (heap->size > 0) ? heap->classes[0] : NULL;
}

static void heap_update_key(hfsc_heap_t *heap, uint32_t class_id, uint64_t new_key) {
    if (!heap->indices || class_id >= HFSC_MAX_CLASSES)
        return;
    
    int32_t idx = heap->indices[class_id];
    if (idx < 0 || (uint32_t)idx >= heap->size)
        return;
    
    uint64_t old_key = heap->keys[idx];
    heap->keys[idx] = new_key;
    
    if (new_key < old_key) {
        heap_sift_up(heap, idx);
    } else {
        heap_sift_down(heap, idx);
    }
}

static void heap_remove(hfsc_heap_t *heap, uint32_t class_id) {
    if (!heap->indices || class_id >= HFSC_MAX_CLASSES)
        return;
    
    int32_t idx = heap->indices[class_id];
    if (idx < 0 || (uint32_t)idx >= heap->size)
        return;
    
    heap->size--;
    if ((uint32_t)idx < heap->size) {
        heap->classes[idx] = heap->classes[heap->size];
        heap->keys[idx] = heap->keys[heap->size];
        
        if (heap->indices) {
            heap->indices[heap->classes[idx]->class_id] = idx;
        }
        
        if (idx > 0 && heap->keys[idx] < heap->keys[(idx-1)/2]) {
            heap_sift_up(heap, idx);
        } else {
            heap_sift_down(heap, idx);
        }
    }
    
    heap->indices[class_id] = -1;
}

/* Update cfmin and cl_f */
static void update_cfmin(hfsc_class_t *cl) {
    if (!cl) return;
    cl->cl_cfmin = UINT64_MAX;
    bool has_active = false;

    for (int i = 0; i < cl->num_children; i++) {
        hfsc_class_t *child = cl->children[i];
        if (child->flags.active && child->cl_f < cl->cl_cfmin) {
            cl->cl_cfmin = child->cl_f;
            has_active = true;
        }
    }
    if (!has_active) cl->cl_cfmin = 0;
}

static void compute_cl_f(hfsc_class_t *cl) {
    if (!cl) return;
    cl->cl_f = (cl->cl_myf > cl->cl_cfmin) ? cl->cl_myf : cl->cl_cfmin;
}

/* Activate class */
static void activate_class(hfsc_scheduler_t *sched, hfsc_class_t *cls) {
    if (cls->flags.active)
        return;
    
    uint64_t now = now_cycles();
    double now_sec = cycles_to_sec(now, sched->cycles_per_sec);
    
    cls->flags.active = true;
    cls->flags.backlogged = true;
    cls->last_time = now;
    cls->vtperiod++;
    
    if (cls->parent) {
        cls->parentperiod = cls->parent->vtperiod;
    }
    
    /* Initialize RT curve */
    if (cls->rsc.m1 > 0 || cls->rsc.m2 > 0) {
        init_runtime_curve(&cls->rt_curve, now_sec, cls->cumul,
                          &cls->rsc, sched->cycles_per_sec);
        
        /* Eligibility curve: for convex RSC, use m2 only */
        rtsc_copy(&cls->el_curve, &cls->rt_curve);
        if (cls->rsc.type == HFSC_CURVE_CONVEX) {
            cls->el_curve.sm1 = cls->el_curve.sm2;
            cls->el_curve.dx = 0;
            cls->el_curve.dy = 0;
        }
        
        uint32_t next_len = peek_next_len(cls);
        cls->cl_e = (uint64_t)(rtsc_y2x(&cls->el_curve, cls->cumul) * sched->cycles_per_sec);
        cls->cl_d = (uint64_t)(rtsc_y2x(&cls->rt_curve, cls->cumul + next_len) * sched->cycles_per_sec);
        
        heap_push(&sched->rt_heap, cls, cls->cl_d);
    }
    
    /* Initialize LS curve */
    if (cls->fsc.m1 > 0 || cls->fsc.m2 > 0) {
        init_runtime_curve(&cls->ls_curve, now_sec, cls->total,
                          &cls->fsc, sched->cycles_per_sec);
        cls->cl_vt = (uint64_t)(rtsc_y2x(&cls->ls_curve, cls->total) * sched->cycles_per_sec);
        
        heap_push(&sched->ls_heap, cls, cls->cl_vt);
    }
    
    /* Initialize UL curve */
    if (cls->usc.m1 > 0 || cls->usc.m2 > 0) {
        init_runtime_curve(&cls->ul_curve, now_sec, cls->total,
                          &cls->usc, sched->cycles_per_sec);
        cls->cl_myf = (uint64_t)(rtsc_y2x(&cls->ul_curve, cls->total) * sched->cycles_per_sec);
    } else {
        cls->cl_myf = UINT64_MAX;
    }
    
    /* Compute cl_f and propagate */
    compute_cl_f(cls);
    if (cls->parent) {
        update_cfmin(cls->parent);
        compute_cl_f(cls->parent);
    }
    
    /* Activate parent */
    if (cls->parent && !cls->parent->flags.active) {
        activate_class(sched, cls->parent);
    }
    
    HFSC_LOG(DEBUG, "Class %u '%s' activated", cls->class_id, cls->name);
}

/* ================= PUBLIC API IMPLEMENTATION ================= */

int hfsc_init(hfsc_scheduler_t *sched, uint64_t link_rate_bps) {
    if (!sched)
        return -1;
    
    memset(sched, 0, sizeof(*sched));
    
    sched->cycles_per_sec = rte_get_tsc_hz();
    sched->link_rate = link_rate_bps;
    sched->tick_interval = (sched->cycles_per_sec * HFSC_TICK_INTERVAL_US) / 1000000;
    sched->strict_priority = true;
    sched->enforce_ul = true;
    
    /* Initialize heaps */
    heap_init(&sched->rt_heap, 256, true);
    heap_init(&sched->ls_heap, 256, false);
    
    rte_spinlock_init(&sched->lock);
    
    HFSC_LOG(INFO, "HFSC initialized: link_rate=%lu Bps", link_rate_bps);
    return 0;
}

hfsc_class_t* hfsc_class_create(hfsc_scheduler_t *sched,
                                uint32_t parent_id,
                                const hfsc_service_curve_t *rsc,
                                const hfsc_service_curve_t *fsc,
                                const hfsc_service_curve_t *usc,
                                void *queue_ctx,
                                void* (*queue_peek)(void*),
                                void* (*queue_dequeue)(void*),
                                uint32_t (*queue_len)(void*),
                                bool (*queue_empty)(void*),
                                const char *name) {
    if (!sched || sched->num_classes >= HFSC_MAX_CLASSES)
        return NULL;
    
    rte_spinlock_lock(&sched->lock);
    
    /* Allocate class */
    hfsc_class_t *cls = rte_zmalloc(NULL, sizeof(hfsc_class_t), RTE_CACHE_LINE_SIZE);
    if (!cls) {
        rte_spinlock_unlock(&sched->lock);
        return NULL;
    }
    
    cls->class_id = sched->num_classes++;
    strncpy(cls->name, name ? name : "unnamed", sizeof(cls->name) - 1);
    
    /* Set parent */
    if (parent_id == 0) {
        if (!sched->root) {
            sched->root = cls;
            cls->depth = 0;
        } else {
            rte_spinlock_unlock(&sched->lock);
            rte_free(cls);
            return NULL;
        }
    } else if (parent_id < sched->num_classes) {
        hfsc_class_t *parent = sched->classes[parent_id];
        if (parent && parent->num_children < HFSC_MAX_CHILDREN) {
            parent->children[parent->num_children++] = cls;
            cls->parent = parent;
            cls->depth = parent->depth + 1;
        }
    }
    
    /* Set ALL THREE curves */
    if (rsc) cls->rsc = *rsc;
    if (fsc) cls->fsc = *fsc;
    if (usc) cls->usc = *usc;
    
    /* Set queue interface */
    cls->queue_ctx = queue_ctx;
    cls->queue_ops.peek = queue_peek;
    cls->queue_ops.dequeue = queue_dequeue;
    cls->queue_ops.len = queue_len;
    cls->queue_ops.empty = queue_empty;
    
    /* Create internal queue if no custom queue provided */
    if (!queue_ctx && (rsc || fsc)) {
        char ring_name[32];
        snprintf(ring_name, sizeof(ring_name), "hfsc_q_%u", cls->class_id);
        cls->q = rte_ring_create(ring_name, HFSC_QUEUE_SIZE, 
                                 rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (!cls->q) {
            rte_spinlock_unlock(&sched->lock);
            rte_free(cls);
            return NULL;
        }
    }
    
    cls->is_leaf = (queue_ctx != NULL) || (cls->q != NULL);
    
    /* Initialize heap indices */
    cls->rt_heap_idx = -1;
    cls->ls_heap_idx = -1;
    
    /* Initialize cl_f values */
    cls->cl_cfmin = 0;
    cls->cl_f = cls->cl_myf = UINT64_MAX;
    
    /* Add to class array */
    sched->classes[cls->class_id] = cls;
    
    HFSC_LOG(INFO, "Created class %u '%s' (parent=%u, leaf=%d)",
             cls->class_id, cls->name, parent_id, cls->is_leaf);
    
    rte_spinlock_unlock(&sched->lock);
    return cls;
}

int hfsc_notify_enqueue(hfsc_scheduler_t *sched, uint32_t class_id, uint32_t pkt_len) {
    if (!sched || class_id >= sched->num_classes)
        return -1;
    
    hfsc_class_t *cls = sched->classes[class_id];
    if (!cls || !cls->is_leaf)
        return -1;
    
    rte_spinlock_lock(&sched->lock);
    
    if (!cls->flags.active) {
        activate_class(sched, cls);
    }
    
    cls->flags.backlogged = true;
    
    rte_spinlock_unlock(&sched->lock);
    return 0;
}

hfsc_class_t* hfsc_schedule(hfsc_scheduler_t *sched, hfsc_decision_t *decision) {
    if (!sched || !decision)
        return NULL;
    
    rte_spinlock_lock(&sched->lock);
    
    uint64_t now = now_cycles();
    hfsc_class_t *selected = NULL;
    *decision = HFSC_DECISION_NONE;
    
    /* Step 1: REAL-TIME criterion */
    if (sched->strict_priority) {
        hfsc_class_t *rt_candidate = heap_peek(&sched->rt_heap);
        if (rt_candidate && 
            rt_candidate->cl_e <= now && 
            (!sched->enforce_ul || rt_candidate->cl_myf <= now)) {
            
            /* Check if class has packets */
            bool has_packets = false;
            if (rt_candidate->queue_ops.len) {
                has_packets = (rt_candidate->queue_ops.len(rt_candidate->queue_ctx) > 0);
            } else if (rt_candidate->q) {
                has_packets = !rte_ring_empty(rt_candidate->q);
            }
            
            if (has_packets) {
                selected = rt_candidate;
                *decision = HFSC_DECISION_RT;
                sched->stats.rt_decisions++;
            }
        }
    }
    
    /* Step 2: LINK-SHARING criterion */
    if (!selected) {
        /* Find class with minimum virtual time under UL constraint */
        for (uint32_t i = 0; i < sched->ls_heap.size; i++) {
            hfsc_class_t *ls_candidate = sched->ls_heap.classes[i];
            
            if ((!sched->enforce_ul || ls_candidate->cl_myf <= now)) {
                
                /* Check if class has packets */
                bool has_packets = false;
                if (ls_candidate->queue_ops.len) {
                    has_packets = (ls_candidate->queue_ops.len(ls_candidate->queue_ctx) > 0);
                } else if (ls_candidate->q) {
                    has_packets = !rte_ring_empty(ls_candidate->q);
                }
                
                if (has_packets) {
                    selected = ls_candidate;
                    *decision = HFSC_DECISION_LS;
                    sched->stats.ls_decisions++;
                    break;
                }
            }
        }
    }
    
    /* Step 3: UL blocked */
    if (!selected && sched->enforce_ul) {
        *decision = HFSC_DECISION_UL;
        sched->stats.ul_blocks++;
    }
    
    rte_spinlock_unlock(&sched->lock);
    return selected;
}

void hfsc_update_service(hfsc_scheduler_t *sched, hfsc_class_t *cls, 
                         uint32_t pkt_len, hfsc_decision_t decision) {
    if (!sched || !cls || pkt_len == 0)
        return;
    
    rte_spinlock_lock(&sched->lock);
    
    uint64_t now = now_cycles();
    double now_sec = cycles_to_sec(now, sched->cycles_per_sec);
    uint64_t hz = sched->cycles_per_sec;
    
    /* Update service counters */
    cls->total += pkt_len;
    if (decision == HFSC_DECISION_RT) {
        cls->cumul += pkt_len;
        cls->stats.packets_rt++;
        cls->stats.bytes_rt += pkt_len;
    } else if (decision == HFSC_DECISION_LS) {
        cls->stats.packets_ls++;
        cls->stats.bytes_ls += pkt_len;
    }
    
    /* Update ALL THREE curves */
    
    /* 1. RT curve */
    if (cls->rsc.m1 > 0 || cls->rsc.m2 > 0) {
        rtsc_min(&cls->rt_curve, now_sec, cls->cumul,
                bps_to_bpcycle(cls->rsc.m1, hz),
                bps_to_bpcycle(cls->rsc.m2, hz),
                (double)cls->rsc.d / 1000000.0);
        
        /* Update eligibility curve */
        rtsc_copy(&cls->el_curve, &cls->rt_curve);
        if (cls->rsc.type == HFSC_CURVE_CONVEX) {
            cls->el_curve.sm1 = cls->el_curve.sm2;
            cls->el_curve.dx = 0;
            cls->el_curve.dy = 0;
        }
        
        /* Recalculate times */
        cls->cl_e = (uint64_t)(rtsc_y2x(&cls->el_curve, cls->cumul) * hz);
        
        uint32_t next_len = peek_next_len(cls);
        cls->cl_d = (uint64_t)(rtsc_y2x(&cls->rt_curve, cls->cumul + next_len) * hz);
        
        /* Update heap */
        heap_update_key(&sched->rt_heap, cls->class_id, cls->cl_d);
    }
    
    /* 2. LS curve */
    if (cls->fsc.m1 > 0 || cls->fsc.m2 > 0) {
        rtsc_min(&cls->ls_curve, now_sec, cls->total,
                bps_to_bpcycle(cls->fsc.m1, hz),
                bps_to_bpcycle(cls->fsc.m2, hz),
                (double)cls->fsc.d / 1000000.0);
        
        cls->cl_vt = (uint64_t)(rtsc_y2x(&cls->ls_curve, cls->total) * hz);
        heap_update_key(&sched->ls_heap, cls->class_id, cls->cl_vt);
    }
    
    /* 3. UL curve */
    if (cls->usc.m1 > 0 || cls->usc.m2 > 0) {
        rtsc_min(&cls->ul_curve, now_sec, cls->total,
                bps_to_bpcycle(cls->usc.m1, hz),
                bps_to_bpcycle(cls->usc.m2, hz),
                (double)cls->usc.d / 1000000.0);
        
        uint64_t new_cl_myf = (uint64_t)(rtsc_y2x(&cls->ul_curve, cls->total) * hz);
        
        /* Check UL violation */
        if (now < new_cl_myf) {
            cls->cl_myf = new_cl_myf;
            cls->flags.under_limit = true;
        } else {
            cls->flags.under_limit = false;
            cls->stats.ul_violations++;
        }
    } else {
        cls->flags.under_limit = true;
    }
    
    /* Update cl_f and propagate */
    compute_cl_f(cls);
    if (cls->parent) {
        update_cfmin(cls->parent);
        compute_cl_f(cls->parent);
    }
    
    /* Check if class becomes inactive */
    bool is_empty = false;
    if (cls->queue_ops.empty) {
        is_empty = cls->queue_ops.empty(cls->queue_ctx);
    } else if (cls->q) {
        is_empty = rte_ring_empty(cls->q);
    }
    
    if (is_empty) {
        cls->flags.active = false;
        cls->flags.backlogged = false;
        
        /* Remove from heaps */
        if (cls->rt_heap_idx >= 0) {
            heap_remove(&sched->rt_heap, cls->class_id);
            cls->rt_heap_idx = -1;
        }
        if (cls->ls_heap_idx >= 0) {
            heap_remove(&sched->ls_heap, cls->class_id);
            cls->ls_heap_idx = -1;
        }
        
        /* Update parent's cfmin */
        if (cls->parent) {
            update_cfmin(cls->parent);
            compute_cl_f(cls->parent);
        }
        
        cls->vt_period++; /* New period when reactivated */
    }
    
    cls->last_time = now;
    sched->stats.curve_updates++;
    sched->stats.total_packets++;
    sched->stats.total_bytes += pkt_len;
    
    rte_spinlock_unlock(&sched->lock);
}

void hfsc_tick(hfsc_scheduler_t *sched) {
    if (!sched)
        return;
    
    uint64_t now = now_cycles();
    
    /* Only run periodically */
    if (now - sched->last_tick < sched->tick_interval)
        return;
    
    sched->last_tick = now;
    
    /* Update UL status for all active classes */
    rte_spinlock_lock(&sched->lock);
    
    for (uint32_t i = 0; i < sched->num_classes; i++) {
        hfsc_class_t *cls = sched->classes[i];
        if (!cls || !cls->flags.active || cls->usc.m1 == 0)
            continue;
        
        /* Check if still under UL */
        cls->flags.under_limit = (now < cls->cl_myf);
    }
    
    rte_spinlock_unlock(&sched->lock);
}

void hfsc_cleanup(hfsc_scheduler_t *sched) {
    if (!sched)
        return;
    
    rte_spinlock_lock(&sched->lock);
    
    /* Free all classes */
    for (uint32_t i = 0; i < sched->num_classes; i++) {
        if (sched->classes[i]) {
            if (sched->classes[i]->q) {
                rte_ring_free(sched->classes[i]->q);
            }
            rte_free(sched->classes[i]);
        }
    }
    
    /* Free heap memory */
    if (sched->rt_heap.classes) rte_free(sched->rt_heap.classes);
    if (sched->rt_heap.keys) rte_free(sched->rt_heap.keys);
    if (sched->rt_heap.indices) rte_free(sched->rt_heap.indices);
    
    if (sched->ls_heap.classes) rte_free(sched->ls_heap.classes);
    if (sched->ls_heap.keys) rte_free(sched->ls_heap.keys);
    if (sched->ls_heap.indices) rte_free(sched->ls_heap.indices);
    
    memset(sched, 0, sizeof(*sched));
    
    rte_spinlock_unlock(&sched->lock);
}


/* Example class creation using your format */
void setup_hfsc_classes(hfsc_scheduler_t *sched) {
    /* Root class */
    hfsc_class_t *root = hfsc_class_create(
        sched,
        0,  /* parent_id = 0 for root */
        &(hfsc_service_curve_t){12500000, 0, 12500000, 1500, HFSC_CURVE_LINEAR},  /* RSC */
        &(hfsc_service_curve_t){12500000, 0, 12500000, 1500, HFSC_CURVE_LINEAR},  /* FSC */
        &(hfsc_service_curve_t){12500000, 0, 12500000, 1500, HFSC_CURVE_CONCAVE}, /* USC */
        NULL, NULL, NULL, NULL, NULL,  /* No queue for root */
        "root"
    );
    
    /* Site 1 - 50 Mbps */
    hfsc_class_t *site1 = hfsc_class_create(
        sched,
        root->class_id,
        &(hfsc_service_curve_t){6250000, 0, 6250000, 1500, HFSC_CURVE_LINEAR},
        &(hfsc_service_curve_t){6250000, 0, 6250000, 1500, HFSC_CURVE_LINEAR},
        &(hfsc_service_curve_t){7500000, 0, 7500000, 1500, HFSC_CURVE_CONCAVE},
        NULL, NULL, NULL, NULL, NULL,
        "site1"
    );
    
    /* UDP flow 1 - concave RT + USC */
    hfsc_class_t *udp1 = hfsc_class_create(
        sched,
        site1->class_id,
        &hfsc_rt_curve(5000000, 1250000, 10000, 9000),
        &hfsc_ls_curve(1250000, 9000),
        &hfsc_ul_curve(2000000, 20000, 9000),
        my_udp1_queue,  /* Your custom queue */
        my_queue_peek, my_queue_dequeue, my_queue_len, my_queue_empty,
        "udp1"
    );
    
    /* TCP flow 1 - linear */
    hfsc_class_t *tcp1 = hfsc_class_create(
        sched,
        site1->class_id,
        &hfsc_rt_curve(5000000, 5000000, 0, 1500),
        &hfsc_ls_curve(5000000, 1500),
        &hfsc_ul_curve(6000000, 10000, 1500),
        my_tcp1_queue,
        my_queue_peek, my_queue_dequeue, my_queue_len, my_queue_empty,
        "tcp1"
    );
    
    /* Site 2 - 50 Mbps */
    hfsc_class_t *site2 = hfsc_class_create(
        sched,
        root->class_id,
        &(hfsc_service_curve_t){6250000, 0, 6250000, 1500, HFSC_CURVE_LINEAR},
        &(hfsc_service_curve_t){6250000, 0, 6250000, 1500, HFSC_CURVE_LINEAR},
        &(hfsc_service_curve_t){7500000, 0, 7500000, 1500, HFSC_CURVE_CONCAVE},
        NULL, NULL, NULL, NULL, NULL,
        "site2"
    );
    
    /* UDP flow 2 */
    hfsc_class_t *udp2 = hfsc_class_create(
        sched,
        site2->class_id,
        &hfsc_rt_curve(5000000, 1250000, 10000, 9000),
        &hfsc_ls_curve(1250000, 9000),
        &hfsc_ul_curve(2000000, 20000, 9000),
        my_udp2_queue,
        my_queue_peek, my_queue_dequeue, my_queue_len, my_queue_empty,
        "udp2"
    );
    
    /* TCP flow 2 */
    hfsc_class_t *tcp2 = hfsc_class_create(
        sched,
        site2->class_id,
        &hfsc_rt_curve(5000000, 5000000, 0, 1500),
        &hfsc_ls_curve(5000000, 1500),
        &hfsc_ul_curve(6000000, 10000, 1500),
        my_tcp2_queue,
        my_queue_peek, my_queue_dequeue, my_queue_len, my_queue_empty,
        "tcp2"
    );
}


/*********************************************************************************** */
/************************************************************************************* */


/********************************************************************
 * HFSC Implementation - Complete with hierarchical scheduling
 * Faithful to SIGCOMM '97 paper with proper RT, LS, UL curves
 ********************************************************************/

#include "hfsc.h"
#include <stdlib.h>
#include <string.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_cycles.h>

#define HFSC_LOG(level, fmt, ...) \
    RTE_LOG(level, USER1, "HFSC: " fmt "\n", ##__VA_ARGS__)

/* ================= FIXED-POINT MATH ================= */

static inline uint64_t hfsc_time_from_cycles(uint64_t cycles, uint64_t cycles_per_hfsc) {
    return cycles / cycles_per_hfsc;
}

static inline uint64_t cycles_from_hfsc_time(uint64_t hfsc_time, uint64_t cycles_per_hfsc) {
    return hfsc_time * cycles_per_hfsc;
}

static inline uint64_t bps_to_hfsc_rate(uint64_t bps, uint64_t cycles_per_sec, 
                                       uint64_t cycles_per_hfsc) {
    uint64_t bytes_per_cycle = (bps << HFSC_SCALE_BITS) / cycles_per_sec;
    return (bytes_per_cycle * cycles_per_hfsc) >> HFSC_SCALE_BITS;
}

static inline uint64_t us_to_hfsc_time(uint64_t us, uint64_t cycles_per_sec,
                                      uint64_t cycles_per_hfsc) {
    uint64_t cycles = (us * cycles_per_sec) / 1000000ULL;
    return cycles / cycles_per_hfsc;
}

/* ================= CURVE MATH ================= */

static uint64_t rtsc_x2y(const hfsc_runtime_t *rt, uint64_t x) {
    if (x <= rt->x) return rt->y;
    
    uint64_t delta = x - rt->x;
    if (delta <= rt->dx) {
        uint64_t delta_y = (delta * rt->sm1) >> HFSC_SCALE_BITS;
        return rt->y + delta_y;
    }
    
    uint64_t delta2 = delta - rt->dx;
    uint64_t delta_y2 = (delta2 * rt->sm2) >> HFSC_SCALE_BITS;
    return rt->y + rt->dy + delta_y2;
}

static uint64_t rtsc_y2x(const hfsc_runtime_t *rt, uint64_t y) {
    if (y <= rt->y) return rt->x;
    
    uint64_t delta_y = y - rt->y;
    if (delta_y <= rt->dy) {
        if (rt->sm1 == 0) return rt->x + rt->dx;
        uint64_t delta = (delta_y << HFSC_SCALE_BITS) / rt->sm1;
        return rt->x + delta;
    }
    
    uint64_t delta_y2 = delta_y - rt->dy;
    if (rt->sm2 == 0) return UINT64_MAX;
    uint64_t delta2 = (delta_y2 << HFSC_SCALE_BITS) / rt->sm2;
    return rt->x + rt->dx + delta2;
}

static void rtsc_min(hfsc_runtime_t *rt,
                     uint64_t new_x,
                     uint64_t new_y,
                     uint64_t sm1,
                     uint64_t sm2,
                     uint64_t dx) {
    uint64_t y1 = rtsc_x2y(rt, new_x);
    uint64_t dy_new = (dx * sm1) >> HFSC_SCALE_BITS;
    
    /* Convex */
    if (sm1 <= sm2) {
        if (y1 < new_y) return;
        rt->x = new_x;
        rt->y = new_y;
        rt->sm1 = sm1;
        rt->sm2 = sm2;
        rt->dx = dx;
        rt->dy = dy_new;
        return;
    }
    
    /* Concave */
    uint64_t y2 = rtsc_x2y(rt, new_x + dx);
    if (y2 <= new_y + dy_new) {
        rt->x = new_x;
        rt->y = new_y;
        rt->sm1 = sm1;
        rt->sm2 = sm2;
        rt->dx = dx;
        rt->dy = dy_new;
        return;
    }
    
    /* Intersection */
    if (sm1 > sm2) {
        uint64_t diff = y1 - new_y;
        uint64_t dsm = sm1 - sm2;
        uint64_t new_dx = (diff << HFSC_SCALE_BITS) / dsm;
        if (new_dx > dx) new_dx = dx;
        uint64_t new_dy = (new_dx * sm1) >> HFSC_SCALE_BITS;
        
        rt->x = new_x;
        rt->y = new_y;
        rt->sm1 = sm1;
        rt->sm2 = sm2;
        rt->dx = new_dx;
        rt->dy = new_dy;
    }
}

/* ================= HIERARCHICAL SELECTION ================= */

static hfsc_class_t* select_rt(hfsc_class_t *cl, uint64_t now_hfsc) {
    if (!cl->flags.active) return NULL;
    
    if (cl->is_leaf && cl->flags.eligible && cl->cl_e <= now_hfsc) {
        if (cl->cl_f <= now_hfsc) {
            return cl;
        }
    }
    
    hfsc_class_t *best = NULL;
    uint64_t best_deadline = UINT64_MAX;
    
    for (int i = 0; i < cl->num_children; i++) {
        hfsc_class_t *child = cl->children[i];
        hfsc_class_t *candidate = select_rt(child, now_hfsc);
        
        if (candidate && candidate->cl_d < best_deadline) {
            best = candidate;
            best_deadline = candidate->cl_d;
        }
    }
    
    return best;
}

static hfsc_class_t* select_ls(hfsc_class_t *cl, uint64_t now_hfsc) {
    if (!cl->flags.active) return NULL;
    
    if (cl->cl_f > now_hfsc) {
        cl->flags.ul_blocked = true;
        cl->next_fit = cl->cl_f;
        return NULL;
    }
    cl->flags.ul_blocked = false;
    
    if (cl->is_leaf) {
        return cl;
    }
    
    hfsc_class_t *best = NULL;
    uint64_t best_fit = UINT64_MAX;
    
    for (int i = 0; i < cl->num_children; i++) {
        hfsc_class_t *child = cl->children[i];
        if (!child->flags.active) continue;
        
        hfsc_class_t *candidate = select_ls(child, now_hfsc);
        if (!candidate) continue;
        
        uint64_t candidate_fit = candidate->cl_f;
        if (candidate_fit < best_fit) {
            best = candidate;
            best_fit = candidate_fit;
        }
    }
    
    return best;
}

/* ================= CLASS MANAGEMENT ================= */

static void init_curve(hfsc_runtime_t *rt,
                      uint64_t now_hfsc,
                      uint64_t start_bytes,
                      const hfsc_curve_t *sc,
                      uint64_t cycles_per_sec,
                      uint64_t cycles_per_hfsc) {
    uint64_t sm1 = bps_to_hfsc_rate(sc->m1, cycles_per_sec, cycles_per_hfsc);
    uint64_t sm2 = bps_to_hfsc_rate(sc->m2, cycles_per_sec, cycles_per_hfsc);
    uint64_t dx = sc->d;
    
    rt->x = now_hfsc;
    rt->y = start_bytes;
    rt->sm1 = sm1;
    rt->sm2 = sm2;
    rt->dx = dx;
    rt->dy = (dx * sm1) >> HFSC_SCALE_BITS;
}

static uint32_t peek_next_len(hfsc_class_t *cls) {
    if (cls->queue_ops.peek) {
        void *pkt = cls->queue_ops.peek(cls->queue_ctx);
        if (pkt) {
            return rte_pktmbuf_pkt_len((struct rte_mbuf *)pkt);
        }
    }
    return cls->rsc.umax ? cls->rsc.umax : HFSC_AVG_PKT_LEN;
}

static void update_cfmin(hfsc_class_t *cl) {
    if (!cl || cl->is_leaf) return;
    
    cl->cl_cfmin = UINT64_MAX;
    bool has_active = false;
    
    for (int i = 0; i < cl->num_children; i++) {
        hfsc_class_t *child = cl->children[i];
        if (child->flags.active && child->cl_f < cl->cl_cfmin) {
            cl->cl_cfmin = child->cl_f;
            has_active = true;
        }
    }
    
    if (!has_active) {
        cl->cl_cfmin = 0;
    }
}

static void compute_cl_f(hfsc_class_t *cl) {
    if (!cl) return;
    
    cl->cl_f = (cl->cl_myf > cl->cl_cfmin) ? cl->cl_myf : cl->cl_cfmin;
    
    if (cl->cl_f < cl->last_service) {
        cl->cl_f = cl->last_service;
    }
}

static void activate_class(hfsc_scheduler_t *sched, hfsc_class_t *cls) {
    if (cls->flags.active) return;
    
    uint64_t now_cycles = rte_get_tsc_cycles();
    uint64_t now_hfsc = hfsc_time_from_cycles(now_cycles, sched->cycles_per_hfsc);
    
    cls->flags.active = true;
    cls->flags.backlogged = true;
    cls->last_service = now_hfsc;
    
    /* Virtual time period tracking */
    cls->vt.period++;
    cls->vt.period_start = now_hfsc;
    if (cls->parent) {
        cls->vt.parent_period = cls->parent->vt.period;
    }
    
    uint64_t cycles_per_sec = sched->cycles_per_hfsc * HFSC_ONE_SECOND;
    
    /* Initialize RT curve */
    if (cls->rsc.m1 > 0 || cls->rsc.m2 > 0) {
        init_curve(&cls->rt_curve, now_hfsc, cls->cumul,
                  &cls->rsc, cycles_per_sec, sched->cycles_per_hfsc);
        
        /* Eligibility curve */
        cls->el_curve = cls->rt_curve;
        if (cls->rsc.m1 <= cls->rsc.m2) {
            cls->el_curve.sm1 = cls->el_curve.sm2;
            cls->el_curve.dx = 0;
            cls->el_curve.dy = 0;
        }
        
        cls->cl_e = rtsc_y2x(&cls->el_curve, cls->cumul);
        
        uint32_t next_len = peek_next_len(cls);
        cls->cl_d = rtsc_y2x(&cls->rt_curve, cls->cumul + next_len);
        
        cls->flags.eligible = (now_hfsc >= cls->cl_e);
    }
    
    /* Initialize LS curve */
    if (cls->fsc.m1 > 0 || cls->fsc.m2 > 0) {
        init_curve(&cls->ls_curve, now_hfsc, cls->total,
                  &cls->fsc, cycles_per_sec, sched->cycles_per_hfsc);
        cls->cl_vt = rtsc_y2x(&cls->ls_curve, cls->total);
    }
    
    /* Initialize UL curve */
    if (cls->usc.m1 > 0 || cls->usc.m2 > 0) {
        init_curve(&cls->ul_curve, now_hfsc, cls->total,
                  &cls->usc, cycles_per_sec, sched->cycles_per_hfsc);
        cls->cl_myf = rtsc_y2x(&cls->ul_curve, cls->total);
    } else {
        cls->cl_myf = UINT64_MAX;
    }
    
    /* Initialize fit times */
    cls->cl_cfmin = UINT64_MAX;
    compute_cl_f(cls);
    cls->next_fit = cls->cl_f;
    
    /* Activate parent */
    if (cls->parent && !cls->parent->flags.active) {
        activate_class(sched, cls->parent);
    }
    
    /* Update parent's cfmin */
    if (cls->parent) {
        update_cfmin(cls->parent);
        compute_cl_f(cls->parent);
    }
}

/* ================= PUBLIC API IMPLEMENTATION ================= */

int hfsc_init(hfsc_scheduler_t *sched, uint64_t link_rate_bps) {
    if (!sched) return -1;
    
    memset(sched, 0, sizeof(*sched));
    
    uint64_t cycles_per_sec = rte_get_tsc_hz();
    
    sched->cycles_per_hfsc = cycles_per_sec / HFSC_ONE_SECOND;
    if (sched->cycles_per_hfsc == 0) {
        sched->cycles_per_hfsc = 1;
    }
    
    sched->link_rate = bps_to_hfsc_rate(link_rate_bps, cycles_per_sec, sched->cycles_per_hfsc);
    sched->tick_interval = (sched->cycles_per_hfsc * HFSC_ONE_SECOND) / 10000;
    sched->enforce_hierarchy = true;
    
    rte_spinlock_init(&sched->lock);
    
    HFSC_LOG(INFO, "HFSC initialized: link_rate=%lu Bps", link_rate_bps);
    
    return 0;
}

hfsc_class_t* hfsc_class_create(hfsc_scheduler_t *sched,
                               uint32_t parent_id,
                               uint64_t rsc_m1, uint64_t rsc_m2, uint64_t rsc_d,
                               uint64_t fsc_m1, uint64_t fsc_m2,
                               uint64_t usc_m1, uint64_t usc_m2, uint64_t usc_d,
                               void *queue_ctx,
                               void* (*queue_peek)(void*),
                               void* (*queue_dequeue)(void*),
                               uint32_t (*queue_len)(void*),
                               bool (*queue_empty)(void*),
                               const char *name) {
    if (!sched || sched->num_classes >= HFSC_MAX_CLASSES)
        return NULL;
    
    rte_spinlock_lock(&sched->lock);
    
    hfsc_class_t *cls = rte_zmalloc(NULL, sizeof(hfsc_class_t), RTE_CACHE_LINE_SIZE);
    if (!cls) {
        rte_spinlock_unlock(&sched->lock);
        return NULL;
    }
    
    cls->class_id = sched->num_classes++;
    strncpy(cls->name, name ? name : "unnamed", sizeof(cls->name) - 1);
    
    /* Set parent */
    if (parent_id == 0) {
        if (!sched->root) {
            sched->root = cls;
            cls->depth = 0;
        } else {
            rte_spinlock_unlock(&sched->lock);
            rte_free(cls);
            return NULL;
        }
    } else if (parent_id < sched->num_classes) {
        hfsc_class_t *parent = sched->classes[parent_id];
        if (parent && parent->num_children < HFSC_MAX_CHILDREN) {
            parent->children[parent->num_children++] = cls;
            cls->parent = parent;
            cls->depth = parent->depth + 1;
        }
    }
    
    /* Convert rates to fixed-point */
    uint64_t cycles_per_sec = sched->cycles_per_hfsc * HFSC_ONE_SECOND;
    
    /* Real-time curve */
    if (rsc_m1 > 0 || rsc_m2 > 0) {
        cls->rsc.m1 = bps_to_hfsc_rate(rsc_m1, cycles_per_sec, sched->cycles_per_hfsc);
        cls->rsc.m2 = bps_to_hfsc_rate(rsc_m2, cycles_per_sec, sched->cycles_per_hfsc);
        cls->rsc.d = us_to_hfsc_time(rsc_d, cycles_per_sec, sched->cycles_per_hfsc);
        cls->rsc.umax = 1500;
    }
    
    /* Fair/link-sharing curve */
    if (fsc_m1 > 0 || fsc_m2 > 0) {
        cls->fsc.m1 = bps_to_hfsc_rate(fsc_m1, cycles_per_sec, sched->cycles_per_hfsc);
        cls->fsc.m2 = bps_to_hfsc_rate(fsc_m2, cycles_per_sec, sched->cycles_per_hfsc);
        cls->fsc.d = 0;
        cls->fsc.umax = 1500;
    }
    
    /* Upper limit curve */
    if (usc_m1 > 0 || usc_m2 > 0) {
        cls->usc.m1 = bps_to_hfsc_rate(usc_m1, cycles_per_sec, sched->cycles_per_hfsc);
        cls->usc.m2 = bps_to_hfsc_rate(usc_m2, cycles_per_sec, sched->cycles_per_hfsc);
        cls->usc.d = us_to_hfsc_time(usc_d, cycles_per_sec, sched->cycles_per_hfsc);
        cls->usc.umax = 1500;
    }
    
    /* Queue interface */
    cls->queue_ctx = queue_ctx;
    cls->queue_ops.peek = queue_peek;
    cls->queue_ops.dequeue = queue_dequeue;
    cls->queue_ops.len = queue_len;
    cls->queue_ops.empty = queue_empty;
    
    cls->is_leaf = (queue_ctx != NULL);
    
    /* Initialize fit times */
    cls->cl_cfmin = 0;
    cls->cl_f = UINT64_MAX;
    cls->cl_myf = UINT64_MAX;
    cls->next_fit = UINT64_MAX;
    
    /* Add to class array */
    sched->classes[cls->class_id] = cls;
    
    HFSC_LOG(INFO, "Created class %u '%s' depth=%d leaf=%d",
             cls->class_id, cls->name, cls->depth, cls->is_leaf);
    
    rte_spinlock_unlock(&sched->lock);
    return cls;
}

int hfsc_enqueue(hfsc_scheduler_t *sched, uint32_t class_id, uint32_t pkt_len) {
    if (!sched || class_id >= sched->num_classes)
        return -1;
    
    hfsc_class_t *cls = sched->classes[class_id];
    if (!cls || !cls->is_leaf)
        return -1;
    
    rte_spinlock_lock(&sched->lock);
    
    if (!cls->flags.active) {
        activate_class(sched, cls);
    }
    
    cls->flags.backlogged = true;
    
    rte_spinlock_unlock(&sched->lock);
    return 0;
}

hfsc_class_t* hfsc_schedule(hfsc_scheduler_t *sched) {
    if (!sched || !sched->root)
        return NULL;
    
    rte_spinlock_lock(&sched->lock);
    
    uint64_t now_cycles = rte_get_tsc_cycles();
    uint64_t now_hfsc = hfsc_time_from_cycles(now_cycles, sched->cycles_per_hfsc);
    sched->current_hfsc = now_hfsc;
    
    hfsc_class_t *selected = NULL;
    
    /* TRUE HIERARCHICAL SELECTION - RT first */
    selected = select_rt(sched->root, now_hfsc);
    if (selected) {
        sched->stats.rt_decisions++;
    }
    
    /* TRUE HIERARCHICAL SELECTION - LS second */
    if (!selected) {
        selected = select_ls(sched->root, now_hfsc);
        if (selected) {
            sched->stats.ls_decisions++;
        }
    }
    
    rte_spinlock_unlock(&sched->lock);
    return selected;
}

void hfsc_update(hfsc_scheduler_t *sched, hfsc_class_t *cls, 
                uint32_t pkt_len, bool is_rt) {
    if (!sched || !cls || pkt_len == 0)
        return;
    
    rte_spinlock_lock(&sched->lock);
    
    uint64_t now_cycles = rte_get_tsc_cycles();
    uint64_t now_hfsc = hfsc_time_from_cycles(now_cycles, sched->cycles_per_hfsc);
    
    /* Update service counters */
    cls->total += pkt_len;
    if (is_rt) {
        cls->cumul += pkt_len;
        cls->stats.packets_rt++;
        cls->stats.bytes_rt += pkt_len;
    } else {
        cls->stats.packets_ls++;
        cls->stats.bytes_ls += pkt_len;
    }
    
    /* Update RT curve */
    if (cls->rsc.m1 > 0 || cls->rsc.m2 > 0) {
        rtsc_min(&cls->rt_curve, now_hfsc, cls->cumul,
                cls->rsc.m1, cls->rsc.m2, cls->rsc.d);
        
        cls->el_curve = cls->rt_curve;
        if (cls->rsc.m1 <= cls->rsc.m2) {
            cls->el_curve.sm1 = cls->el_curve.sm2;
            cls->el_curve.dx = 0;
            cls->el_curve.dy = 0;
        }
        
        cls->cl_e = rtsc_y2x(&cls->el_curve, cls->cumul);
        cls->flags.eligible = (now_hfsc >= cls->cl_e);
        
        uint32_t next_len = peek_next_len(cls);
        cls->cl_d = rtsc_y2x(&cls->rt_curve, cls->cumul + next_len);
    }
    
    /* Update LS curve */
    if (cls->fsc.m1 > 0 || cls->fsc.m2 > 0) {
        rtsc_min(&cls->ls_curve, now_hfsc, cls->total,
                cls->fsc.m1, cls->fsc.m2, cls->fsc.d);
        cls->cl_vt = rtsc_y2x(&cls->ls_curve, cls->total);
    }
    
    /* Update UL curve */
    if (cls->usc.m1 > 0 || cls->usc.m2 > 0) {
        rtsc_min(&cls->ul_curve, now_hfsc, cls->total,
                cls->usc.m1, cls->usc.m2, cls->usc.d);
        cls->cl_myf = rtsc_y2x(&cls->ul_curve, cls->total);
        
        if (now_hfsc < cls->cl_myf) {
            cls->stats.ul_delays++;
            sched->stats.ul_enforced++;
        }
    } else {
        cls->cl_myf = UINT64_MAX;
    }
    
    /* Update fit time */
    cls->cl_f = cls->cl_myf;
    
    /* Update cfmin for interior classes */
    if (!cls->is_leaf) {
        update_cfmin(cls);
        compute_cl_f(cls);
    }
    
    /* Propagate to parent */
    if (cls->parent) {
        hfsc_class_t *parent = cls->parent;
        uint64_t old_cfmin = parent->cl_cfmin;
        
        update_cfmin(parent);
        compute_cl_f(parent);
        
        if (parent->cl_cfmin != old_cfmin) {
            sched->stats.hierarchy_respects++;
        }
    }
    
    /* Check if class becomes inactive */
    bool is_empty = false;
    if (cls->queue_ops.empty) {
        is_empty = cls->queue_ops.empty(cls->queue_ctx);
    }
    
    if (is_empty) {
        cls->flags.active = false;
        cls->flags.backlogged = false;
        
        if (cls->parent) {
            update_cfmin(cls->parent);
            compute_cl_f(cls->parent);
        }
    }
    
    cls->last_service = now_hfsc;
    sched->stats.total_packets++;
    sched->stats.total_bytes += pkt_len;
    
    rte_spinlock_unlock(&sched->lock);
}

void hfsc_tick(hfsc_scheduler_t *sched) {
    if (!sched) return;
    
    uint64_t now_cycles = rte_get_tsc_cycles();
    
    if (now_cycles - sched->last_tick < sched->tick_interval) {
        return;
    }
    
    sched->last_tick = now_cycles;
    sched->current_hfsc = hfsc_time_from_cycles(now_cycles, sched->cycles_per_hfsc);
}

void hfsc_cleanup(hfsc_scheduler_t *sched) {
    if (!sched) return;
    
    rte_spinlock_lock(&sched->lock);
    
    for (uint32_t i = 0; i < sched->num_classes; i++) {
        if (sched->classes[i]) {
            rte_free(sched->classes[i]);
        }
    }
    
    memset(sched, 0, sizeof(*sched));
    
    rte_spinlock_unlock(&sched->lock);
}


/* In your main application */
#include "hfsc.h"

/* Create scheduler */
hfsc_scheduler_t sched;
hfsc_init(&sched, 12500000);  /* 100 Mbps */

/* Create classes using your format */
hfsc_class_t *root = hfsc_class_create(
    &sched,
    0,                     /* parent_id */
    12500000, 12500000, 0, /* RSC: 100 Mbps linear */
    12500000, 12500000,    /* FSC: 100 Mbps */
    12500000, 12500000, 0, /* USC: 100 Mbps limit */
    NULL, NULL, NULL, NULL, NULL,
    "root"
);

/* Site 1 */
hfsc_class_t *site1 = hfsc_class_create(
    &sched,
    root->class_id,
    6250000, 6250000, 0,   /* RSC: 50 Mbps */
    6250000, 6250000,      /* FSC: 50 Mbps */
    7500000, 7500000, 0,   /* USC: 60 Mbps limit */
    NULL, NULL, NULL, NULL, NULL,
    "site1"
);

/* UDP flow */
hfsc_class_t *udp1 = hfsc_class_create(
    &sched,
    site1->class_id,
    5000000, 1250000, 10000,  /* RSC: 40M burst, 10M steady, 10ms */
    1250000, 1250000,         /* FSC: 10 Mbps */
    2000000, 2000000, 20000,  /* USC: 16 Mbps limit, 20ms burst */
    my_udp_queue,             /* Your queue */
    my_peek, my_dequeue, my_len, my_empty,
    "udp1"
);




/* In forwarding loop */
void my_forwarding_loop(hfsc_scheduler_t *sched) {
    while (1) {
        /* RX */
        struct rte_mbuf *rx_pkts[32];
        uint16_t nb_rx = rte_eth_rx_burst(port, queue, rx_pkts, 32);
        
        for (int i = 0; i < nb_rx; i++) {
            uint32_t class_id = my_classify(rx_pkts[i]);
            hfsc_enqueue(sched, class_id, rx_pkts[i]->pkt_len);
            /* Store packet in your queue for class_id */
        }
        
        /* Schedule & TX */
        uint16_t nb_tx = 0;
        while (nb_tx < 32) {
            hfsc_class_t *cls = hfsc_schedule(sched);
            if (!cls) break;
            
            struct rte_mbuf *pkt = cls->queue_ops.dequeue(cls->queue_ctx);
            if (!pkt) break;
            
            bool is_rt = (cls->flags.eligible && cls->cl_e <= sched->current_hfsc);
            hfsc_update(sched, cls, pkt->pkt_len, is_rt);
            
            /* Send packet */
            // rte_eth_tx_burst(...);
            nb_tx++;
        }
        
        /* Periodic maintenance */
        hfsc_tick(sched);
    }
}