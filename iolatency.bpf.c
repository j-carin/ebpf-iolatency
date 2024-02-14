#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "iolatency.h"
#include "bits.bpf.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONCURRENT_IO);
    __type(key, struct request *);
    __type(value, u64);
} io_log SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, SLOTS);
    __type(key, u32);
    __type(value, u64);
} latency_hist SEC(".maps");

SEC("raw_tracepoint/block_rq_insert")
int BPF_PROG(block_rq_insert, struct request *req) {
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&io_log, &req, &ts, BPF_ANY);
    return 0;
}

SEC("raw_tracepoint/block_rq_issue")
int BPF_PROG(block_rq_issue, struct request *req) {
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&io_log, &req, &ts, BPF_ANY);
    return 0;
}


SEC("raw_tracepoint/block_rq_complete")
int BPF_PROG(block_rq_complete, struct request *req) {
    u64 *tsp, delta;
    u64 now = bpf_ktime_get_ns();

    tsp = bpf_map_lookup_elem(&io_log, &req);
    if (!tsp || now < *tsp) {
        return 0;
    }

    bpf_map_delete_elem(&io_log, &req);

    delta = (now - *tsp) / 1000;

    u32 index = 0;
    if (delta == 0) {
        index = 0;
    } else {
        index = log2l(delta);
        if (index >= SLOTS) {
            index = SLOTS - 1;
        }
    }

    u64 *val = bpf_map_lookup_elem(&latency_hist, &index);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }

    return 0;
}

