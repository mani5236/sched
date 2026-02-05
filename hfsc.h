/********************************************************************
 * DPDK HFSC Scheduler – Production Level with All Three Curves
 * Complete implementation of RT, LS, and UL curves
 * Enhanced with proper heap structures, statistics, and thread safety
 ********************************************************************/

#ifndef HFSC_H
#define HFSC_H

#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_cycles.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_ether.h>
#include <rte_byteorder.h>
#include <rte_spinlock.h>
#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

/* ================= CONFIG ================= */
#define HFSC_MAX_CLASSES         2048
#define HFSC_MAX_CHILDREN        32
#define HFSC_QUEUE_SIZE          8192
#define HFSC_AVG_PKT_LEN         1500
#define HFSC_TICK_INTERVAL_US    100     /* Scheduler tick interval */

/* Service curve types */
typedef enum {
    HFSC_CURVE_NONE = 0,
    HFSC_CURVE_LINEAR,
    HFSC_CURVE_CONCAVE,
    HFSC_CURVE_CONVEX
} hfsc_curve_type_t;

/* Scheduling decision */
typedef enum {
    HFSC_DECISION_NONE = 0,
    HFSC_DECISION_RT,      /* Real-time */
    HFSC_DECISION_LS,      /* Link-sharing */
    HFSC_DECISION_UL       /* Upper-limit blocked */
} hfsc_decision_t;

/* ================= SERVICE CURVE ================= */
typedef struct {
    uint64_t m1;          /* bytes/sec - initial slope */
    uint64_t d;           /* us - delay for first segment (0 for linear) */
    uint64_t m2;          /* bytes/sec - asymptotic slope */
    uint64_t umax;        /* Maximum packet size (bytes) */
    hfsc_curve_type_t type;
} hfsc_service_curve_t;

/* ================= RUNTIME SERVICE CURVE ================= */
typedef struct {
    double x;             /* start time (sec) */
    double y;             /* start bytes */
    double sm1;           /* slope 1 (bytes/sec) */
    double sm2;           /* slope 2 (bytes/sec) */
    double dx;            /* x-length of first segment */
    double dy;            /* y-length of first segment */
    uint64_t last_update; /* Last update time (cycles) */
} hfsc_runtime_curve_t;

/* ================= HFSC CLASS ================= */
typedef struct hfsc_class {
    /* Hierarchy */
    struct hfsc_class *parent;
    struct hfsc_class *children[HFSC_MAX_CHILDREN];
    int num_children;
    bool is_leaf;
    int depth;

    /* Queue (leaf classes only) */
    struct rte_ring *q;
    
    /* Custom queue callback for integration */
    void *queue_ctx;
    struct {
        void* (*peek)(void *ctx);
        void* (*dequeue)(void *ctx);
        uint32_t (*len)(void *ctx);
        bool (*empty)(void *ctx);
        uint32_t (*avg_len)(void *ctx); /* Optional */
    } queue_ops;

    /* ALL THREE SERVICE CURVES */
    hfsc_service_curve_t rsc;    /* Real-time Service Curve */
    hfsc_service_curve_t fsc;    /* Fair Service Curve (link-sharing) */
    hfsc_service_curve_t usc;    /* Upper Service Curve (limit) */

    /* Runtime curves */
    hfsc_runtime_curve_t rt_curve;   /* Runtime for RSC */
    hfsc_runtime_curve_t el_curve;   /* Eligibility curve (from RSC) */
    hfsc_runtime_curve_t ls_curve;   /* Runtime for FSC */
    hfsc_runtime_curve_t ul_curve;   /* Runtime for USC */

    /* State variables */
    uint64_t cumul;                 /* RT service (bytes) */
    uint64_t total;                 /* total service (bytes) */
    uint64_t excess;                /* Excess service (bytes) */

    /* Timing (in CPU cycles) */
    uint64_t cl_e;                  /* eligible time (cycles) */
    uint64_t cl_d;                  /* deadline (cycles) */
    uint64_t cl_vt;                 /* virtual time (cycles) */
    uint64_t cl_myf;                /* my fit time (from USC) */
    uint64_t cl_cfmin;              /* min fit time of active children */
    uint64_t cl_f;                  /* final fit time = max(myf, cfmin) */

    /* Period tracking */
    uint32_t vtperiod;              /* current virtual time period */
    uint32_t parentperiod;          /* parent's period when activated */

    /* State flags */
    struct {
        bool active:1;
        bool eligible:1;
        bool backlogged:1;
        bool under_limit:1;         /* Under upper limit constraint */
    } flags;

    uint64_t last_time;             /* last update/activation time */

    /* Statistics */
    struct {
        uint64_t packets_rt;
        uint64_t packets_ls;
        uint64_t bytes_rt;
        uint64_t bytes_ls;
        uint64_t deadline_misses;
        uint64_t ul_violations;
        uint64_t max_queue_delay_ns;
        uint64_t avg_queue_len;
    } stats;

    /* Heap indices for efficient updates */
    int32_t rt_heap_idx;
    int32_t ls_heap_idx;

    /* Class identification */
    uint32_t class_id;
    char name[32];
} hfsc_class_t;

/* ================= MIN-HEAP STRUCTURES ================= */
typedef struct {
    hfsc_class_t **classes;
    uint64_t *keys;
    int32_t *indices;       /* Reverse mapping: class_id -> heap position */
    uint32_t size;
    uint32_t capacity;
    bool is_rt_heap;
} hfsc_heap_t;

/* ================= HFSC SCHEDULER ================= */
typedef struct {
    /* Root class */
    hfsc_class_t *root;
    
    /* Class management */
    hfsc_class_t *classes[HFSC_MAX_CLASSES];
    uint32_t num_classes;
    
    /* Scheduling heaps */
    hfsc_heap_t rt_heap;    /* For RT scheduling (eligible + deadline) */
    hfsc_heap_t ls_heap;    /* For LS scheduling (virtual time) */
    
    /* Timing */
    uint64_t cycles_per_sec;
    uint64_t last_tick;
    uint64_t tick_interval; /* In cycles */
    
    /* Statistics */
    struct {
        uint64_t rt_decisions;
        uint64_t ls_decisions;
        uint64_t ul_blocks;
        uint64_t curve_updates;
        uint64_t total_packets;
        uint64_t total_bytes;
    } stats;
    
    /* Configuration */
    uint64_t link_rate;     /* bytes/sec */
    bool strict_priority;   /* RT always over LS */
    bool enforce_ul;        /* Enforce upper limits */
    
    /* Thread safety */
    rte_spinlock_t lock;
} hfsc_scheduler_t;

/* ================= PUBLIC API ================= */

/* Initialize HFSC scheduler */
int hfsc_init(hfsc_scheduler_t *sched, uint64_t link_rate_bps);

/* Create class with ALL THREE curves */
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
                                const char *name);

/* Notify enqueue */
int hfsc_notify_enqueue(hfsc_scheduler_t *sched, uint32_t class_id, uint32_t pkt_len);

/* Make scheduling decision */
hfsc_class_t* hfsc_schedule(hfsc_scheduler_t *sched, hfsc_decision_t *decision);

/* Update after service */
void hfsc_update_service(hfsc_scheduler_t *sched, hfsc_class_t *cls, 
                         uint32_t pkt_len, hfsc_decision_t decision);

/* Periodic maintenance */
void hfsc_tick(hfsc_scheduler_t *sched);

/* Cleanup */
void hfsc_cleanup(hfsc_scheduler_t *sched);

/* ================= CURVE HELPERS ================= */

static inline hfsc_service_curve_t hfsc_rt_curve(uint64_t burst_rate,
                                                 uint64_t steady_rate,
                                                 uint64_t burst_delay_us,
                                                 uint64_t max_pkt_size) {
    hfsc_curve_type_t type = (burst_rate > steady_rate) ? HFSC_CURVE_CONCAVE :
                             (burst_rate < steady_rate) ? HFSC_CURVE_CONVEX : 
                             HFSC_CURVE_LINEAR;
    return (hfsc_service_curve_t){
        .m1 = burst_rate,
        .m2 = steady_rate,
        .d = burst_delay_us,
        .umax = max_pkt_size,
        .type = type
    };
}

static inline hfsc_service_curve_t hfsc_ls_curve(uint64_t rate_bps, uint64_t max_pkt_size) {
    return (hfsc_service_curve_t){
        .m1 = rate_bps,
        .m2 = rate_bps,
        .d = 0,
        .umax = max_pkt_size,
        .type = HFSC_CURVE_LINEAR
    };
}

static inline hfsc_service_curve_t hfsc_ul_curve(uint64_t max_rate_bps, 
                                                 uint64_t burst_us,
                                                 uint64_t max_pkt_size) {
    return (hfsc_service_curve_t){
        .m1 = max_rate_bps,
        .m2 = max_rate_bps,
        .d = burst_us,
        .umax = max_pkt_size,
        .type = HFSC_CURVE_CONCAVE
    };
}

#endif /* HFSC_H */


/**************************************************************************************** */
/**************************************************************************************** */



/********************************************************************
 * HFSC Header - Hierarchical Fair Service Curve Scheduler
 * Based on SIGCOMM '97 paper by Stoica, Zhang, and Ng
 ********************************************************************/

#ifndef HFSC_H
#define HFSC_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>

/* ================= CONFIG ================= */
#define HFSC_MAX_CLASSES         2048
#define HFSC_MAX_CHILDREN        32
#define HFSC_SCALE_BITS          24      /* Fixed-point scaling */
#define HFSC_ONE_SECOND          (1ULL << HFSC_SCALE_BITS)
#define HFSC_QUEUE_SIZE          8192
#define HFSC_AVG_PKT_LEN         1500

/* Service curve in fixed-point */
typedef struct {
    uint64_t m1;        /* Slope 1 (bytes per HFSC_ONE_SECOND) */
    uint64_t m2;        /* Slope 2 (bytes per HFSC_ONE_SECOND) */
    uint64_t d;         /* Delay (in HFSC time units) */
    uint64_t umax;      /* Maximum packet size (bytes) */
} hfsc_curve_t;

/* Runtime curve state */
typedef struct {
    uint64_t x;         /* Start time (HFSC time units) */
    uint64_t y;         /* Start bytes */
    uint64_t sm1;       /* Slope 1 (bytes per HFSC time unit) */
    uint64_t sm2;       /* Slope 2 (bytes per HFSC time unit) */
    uint64_t dx;        /* Length of first segment */
    uint64_t dy;        /* Bytes in first segment */
} hfsc_runtime_t;

/* HFSC Class */
typedef struct hfsc_class {
    /* Hierarchy */
    struct hfsc_class *parent;
    struct hfsc_class *children[HFSC_MAX_CHILDREN];
    int num_children;
    bool is_leaf;
    int depth;
    
    /* Queue interface */
    void *queue_ctx;
    struct {
        void* (*peek)(void *ctx);
        void* (*dequeue)(void *ctx);
        uint32_t (*len)(void *ctx);
        bool (*empty)(void *ctx);
    } queue_ops;
    
    /* ALL THREE CURVES */
    hfsc_curve_t rsc;    /* Real-time */
    hfsc_curve_t fsc;    /* Fair/link-sharing */
    hfsc_curve_t usc;    /* Upper limit */
    
    /* Runtime states */
    hfsc_runtime_t rt_curve;     /* D(t) */
    hfsc_runtime_t el_curve;     /* E(t) */
    hfsc_runtime_t ls_curve;     /* V(t) */
    hfsc_runtime_t ul_curve;     /* U(t) */
    
    /* Service counters */
    uint64_t cumul;     /* RT service (bytes) */
    uint64_t total;     /* Total service (bytes) */
    
    /* Timing in HFSC time units */
    uint64_t cl_e;      /* Eligible time */
    uint64_t cl_d;      /* Deadline */
    uint64_t cl_vt;     /* Virtual time */
    uint64_t cl_myf;    /* My fit time (from USC) */
    uint64_t cl_cfmin;  /* Min child fit time */
    uint64_t cl_f;      /* Final fit time = max(cl_myf, cl_cfmin) */
    
    /* Period tracking */
    struct {
        uint32_t period;        /* Current period */
        uint32_t parent_period; /* Parent's period when activated */
        uint64_t period_start;  /* When current period started */
    } vt;
    
    /* State flags */
    struct {
        bool active:1;
        bool eligible:1;
        bool backlogged:1;
        bool ul_blocked:1;
    } flags;
    
    /* Statistics */
    struct {
        uint64_t packets_rt;
        uint64_t packets_ls;
        uint64_t bytes_rt;
        uint64_t bytes_ls;
        uint64_t deadline_misses;
        uint64_t ul_delays;
        uint64_t max_queue_delay;
    } stats;
    
    /* Identification */
    uint32_t class_id;
    char name[32];
    
    /* For scheduling */
    uint64_t last_service;
    uint64_t next_fit;
} hfsc_class_t;

/* HFSC Scheduler */
typedef struct {
    /* Root class */
    hfsc_class_t *root;
    
    /* Class management */
    hfsc_class_t *classes[HFSC_MAX_CLASSES];
    uint32_t num_classes;
    
    /* Timing */
    uint64_t cycles_per_hfsc;
    uint64_t current_hfsc;
    uint64_t last_tick;
    uint64_t tick_interval;
    
    /* Configuration */
    uint64_t link_rate;
    bool enforce_hierarchy;
    
    /* Statistics */
    struct {
        uint64_t rt_decisions;
        uint64_t ls_decisions;
        uint64_t hierarchy_respects;
        uint64_t ul_enforced;
        uint64_t total_packets;
        uint64_t total_bytes;
    } stats;
    
    /* Thread safety */
    rte_spinlock_t lock;
} hfsc_scheduler_t;

/* ================= PUBLIC API ================= */

/* Initialize HFSC scheduler */
int hfsc_init(hfsc_scheduler_t *sched, uint64_t link_rate_bps);

/* Create class with ALL THREE curves */
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
                               const char *name);

/* Notify packet enqueue */
int hfsc_enqueue(hfsc_scheduler_t *sched, uint32_t class_id, uint32_t pkt_len);

/* Make scheduling decision */
hfsc_class_t* hfsc_schedule(hfsc_scheduler_t *sched);

/* Update after packet service */
void hfsc_update(hfsc_scheduler_t *sched, hfsc_class_t *cls, 
                uint32_t pkt_len, bool is_rt);

/* Periodic maintenance */
void hfsc_tick(hfsc_scheduler_t *sched);

/* Cleanup */
void hfsc_cleanup(hfsc_scheduler_t *sched);

/* ================= HELPER MACROS ================= */

/* Create linear service curve (for RT or LS) */
#define HFSC_LINEAR_CURVE(rate_bps) \
    { .m1 = rate_bps, .m2 = rate_bps, .d = 0, .umax = 1500 }

/* Create concave RT curve (burst then steady) */
#define HFSC_CONCAVE_RT(burst_bps, steady_bps, delay_us) \
    { .m1 = burst_bps, .m2 = steady_bps, .d = delay_us, .umax = 9000 }

/* Create upper limit curve */
#define HFSC_UPPER_LIMIT(max_bps, burst_us) \
    { .m1 = max_bps, .m2 = max_bps, .d = burst_us, .umax = 1500 }

#endif /* HFSC_H */