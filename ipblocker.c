//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct bpf_map_def SEC("maps") blocked_ips = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 128,
};

struct bpf_map_def SEC("maps") recieved_ips = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 128,
};

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_ABORTED;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_ABORTED;

    __u32 src_ip = ip->saddr;
    __u32 *blocked = bpf_map_lookup_elem(&blocked_ips, &src_ip);

    if (blocked) {
        return XDP_DROP;
    }

    __u32 *recieved = bpf_map_lookup_elem(&recieved_ips, &src_ip);

    if (recieved) {
        __sync_fetch_and_add(recieved, 1);
    }else {
        __u32 init_pkt_count = 1;
		bpf_map_update_elem(&recieved_ips, &ip, &init_pkt_count, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
