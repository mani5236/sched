#ifndef HFSC_H
#define HFSC_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_spinlock.h>
#include <rte_mbuf.h>

/* ================= CONFIG ================= */

#define HFSC_MAX_CLASSES   2048
#define HFSC_MAX_CHILDREN  32
#define HFSC_SCALE_BITS    24
#define HFSC_ONE_SEC_FP    (1ULL << HFSC_SCALE_BITS)
#define HFSC_AVG_PKT_LEN   1500

/* ================= SERVICE CURVES ================= */

/*
 * IMPORTANT FIX:
 * Curves store RAW rates (bytes/sec), NOT pre-scaled.
 * Scaling is applied ONLY in runtime curves.
 */
typedef struct {
    uint64_t m1_bps;
    uint64_t m2_bps;
    uint64_t d_us;
    uint32_t umax;
} hfsc_curve_t;

/*
 * Runtime service curve in fixed-point time
 */
typedef struct {
    uint64_t x;      /* start time (hfsc time) */
    uint64_t y;      /* start bytes */
    uint64_t sm1;    /* slope 1 (bytes / hfsc time) */
    uint64_t sm2;    /* slope 2 (bytes / hfsc time) */
    uint64_t dx;     /* duration of first segment */
    uint64_t dy;     /* bytes in first segment */
} hfsc_runtime_t;

/* ================= HFSC CLASS ================= */

typedef struct hfsc_class {
    struct hfsc_class *parent;
    struct hfsc_class *children[HFSC_MAX_CHILDREN];
    int num_children;
    int depth;
    bool is_leaf;

    /* Packet queue */
    void *queue_ctx;
    struct {
        void* (*peek)(void*);
        void* (*dequeue)(void*);
        uint32_t (*len)(void*);
        bool (*empty)(void*);
    } qops;

    /* Service curves */
    hfsc_curve_t rsc;
    hfsc_curve_t fsc;
    hfsc_curve_t usc;

    /* Runtime curves */
    hfsc_runtime_t rt;
    hfsc_runtime_t el;
    hfsc_runtime_t ls;
    hfsc_runtime_t ul;

    /* Counters */
    uint64_t cumul_rt;
    uint64_t cumul_all;

    /* Scheduling times */
    uint64_t cl_e;
    uint64_t cl_d;
    uint64_t cl_vt;
    uint64_t cl_myf;
    uint64_t cl_cfmin;
    uint64_t cl_f;

    /* State */
    struct {
        bool active;
        bool eligible;
        bool backlogged;
    } flags;

    uint64_t last_service;
    uint64_t next_fit;

    uint32_t class_id;
    char name[32];

} hfsc_class_t;

/* ================= SCHEDULER ================= */

typedef struct {
    hfsc_class_t *root;
    hfsc_class_t *classes[HFSC_MAX_CLASSES];
    uint32_t num_classes;

    uint64_t cycles_per_hfsc;
    uint64_t now;

    rte_spinlock_t lock;
} hfsc_scheduler_t;

/* ================= API ================= */

int hfsc_init(hfsc_scheduler_t *s, uint64_t link_rate_bps);

hfsc_class_t* hfsc_class_create(
    hfsc_scheduler_t *s,
    uint32_t parent_id,
    hfsc_curve_t *rsc,
    hfsc_curve_t *fsc,
    hfsc_curve_t *usc,
    void *queue_ctx,
    void* (*peek)(void*),
    void* (*dequeue)(void*),
    uint32_t (*len)(void*),
    bool (*empty)(void*),
    const char *name
);

int hfsc_enqueue(hfsc_scheduler_t *s, uint32_t class_id);
hfsc_class_t* hfsc_schedule(hfsc_scheduler_t *s);
void hfsc_update(hfsc_scheduler_t *s, hfsc_class_t *cl, uint32_t pkt_len);
void hfsc_tick(hfsc_scheduler_t *s);

#endif /* HFSC_H */
