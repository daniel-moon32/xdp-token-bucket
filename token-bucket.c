#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>

#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#define XDP_SECTION "token_bucket"
#define BATCH_INTERVAL_NS 100000000

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct datarec);
	__uint(max_entries, XDP_ACTION_MAX);
} xdp_stats_map SEC(".maps");

struct datarec {
    __u64 tokens;
};


SEC(XDP_SECTION)
int xdp_prog(struct xdp_md *ctx) {
    const int r = 10;
    struct datarec *rec;
    __u32 key = XDP_PASS; 
    static __u64 last_batch_time = 0;


    rec = bpf_map_lookup_elem(&xdp_stats_map, &key);

    void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
    __u64 bytes = data_end - data;
    __u64 current_time = bpf_ktime_get_ns();

    // Check the time elapsed
    if (current_time - last_batch_time >= BATCH_INTERVAL_NS) {
        last_batch_time = current_time;
    }

    if ((*rec).tokens < bytes) {
        return XDP_DROP;
    }

    __u64 new_tokens = (*rec).tokens + (last_batch_time * r);

    lock_xadd(&rec->tokens, new_tokens);


    return XDP_PASS;
    
}


char _license[] SEC("license") = "GPL";