#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>

#define MAX_IP_ENTRIES 1
#define RATE_LIMIT_RATE 1000000
#define RATE_LIMIT_BURST_SIZE 1000

struct token_bucket {
    __u64 tokens;
    __u64 last_update;
    // __u64 flow_rate;
    __u64 total_packet_size;
    __u64 window_start;
};

struct ip_config {
    __u32 ip;
    __u64 burst_size;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IP_ENTRIES);
    __type(key, __u32);
    __type(value, struct token_bucket);
} ip_token_buckets SEC(".maps");


#define min(x, y) ((x) < (y) ? (x) : (y))
SEC("xdp")
int xdp_token_bucket(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    // if (data + sizeof(struct ethhdr) > data_end)
    //     return XDP_PASS;

    // if (eth->h_proto != __constant_htons(ETH_P_IP))
    //     return XDP_PASS;

    struct iphdr *iph = data + sizeof(*eth);
    if (iph + 1 > data_end) {
        return XDP_PASS;
    }
    // if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    //     return XDP_PASS;

    __u32 src_ip = iph->saddr;

    __u32 predefined_ips[MAX_IP_ENTRIES] = {
        16777343,  
    };

    // Check if the source IP matches one of the predefined IPs
    int is_predefined_ip = 0;
    for (int i = 0; i < MAX_IP_ENTRIES; i++) {
        // bpf_printk("Predefined IP: %u\n", predefined_ips[i]);
        // bpf_printk("Source IP: %u\n", src_ip);
        if (src_ip == predefined_ips[i]) {
            is_predefined_ip = 1;
            break;
        }
    }

    if (!is_predefined_ip)
        return XDP_PASS;  
    
    // bpf_printk("IP: %u\n", src_ip);

    struct token_bucket *bucket;
    bucket = bpf_map_lookup_elem(&ip_token_buckets, &src_ip);
    if (!bucket) {
        struct token_bucket new_bucket = {
            .tokens = RATE_LIMIT_BURST_SIZE,  
            .last_update = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&ip_token_buckets, &src_ip, &new_bucket, BPF_NOEXIST);
        bucket = bpf_map_lookup_elem(&ip_token_buckets, &src_ip);
    }
    if (bucket) {
        __u64 now = bpf_ktime_get_ns();
        __u64 elapsed_ns = now - bucket->last_update;

        __u64 tokens_to_add = elapsed_ns * 100; 
        bucket->tokens = bucket->tokens + tokens_to_add;
        bucket->last_update = now; 

        // windows 10 ms
        __u32 packet_size = ctx->data_end - ctx->data; 

        if (bucket->tokens >= packet_size) {
            bucket->tokens -= packet_size; 
            return XDP_PASS;
        } else {
            return XDP_DROP; 
        }
    } else {
        return XDP_PASS;
    }   
}

char _license[] SEC("license") = "GPL";