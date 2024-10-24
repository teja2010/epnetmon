// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_kfuncs.h"

#define NF_DROP 0
#define NF_ACCEPT 1

struct flow_t {
	__u16 protocol;
	__u32 ipv4_saddr;
	__u32 ipv4_daddr;
	__u16 dport;
	__u16 sport;
};

struct flow_stats_t {
	__u64 bytes;
	__u64 pkts;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, struct flow_t);
	__type(value, struct flow_stats_t);
} count_map SEC(".maps");

//struct {
//	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
//	__uint(max_entries, 1);
//	__type(key, __u32);
//	__array(values, struct count_map_t);
//} counter_map_of_map SEC(".maps");

struct metrics_t {
	__u64 pkt_count;
	__u64 tcp4_pkt_count;
	__u64 flow_not_found;

	// errors
	__u64 err_inner_map_not_found;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct metrics_t);
} metrics_map SEC(".maps");

void *get_metrics()
{
	__u32 key = 0;
	return bpf_map_lookup_elem(&metrics_map, &key);
}

void __nf_count(struct bpf_nf_ctx *ctx)
{
	struct nf_hook_state *state = (struct nf_hook_state *)ctx->state;
	struct sk_buff *skb = ctx->skb;

	struct metrics_t *metrics = get_metrics();
	if (metrics == NULL)
		return;

	struct sock *sk = state->sk;
	if (sk != NULL) {
		u32 sk_uid = (u32)BPF_CORE_READ(sk, sk_uid).val;
		static const char fmt[] = "sk %p uid %d";
		bpf_trace_printk(fmt, sizeof(fmt), sk, sk_uid);
	}

	metrics->pkt_count++;

	const struct iphdr *iph, _iph;
	const struct tcphdr *th, _th;
	struct bpf_dynptr ptr;

	if (bpf_dynptr_from_skb((struct __sk_buff *)skb, 0, &ptr))
		return;

	iph = bpf_dynptr_slice(&ptr, 0, (void *)&_iph, sizeof(_iph));
	if (!iph)
		return;

	if (iph->protocol != IPPROTO_TCP)
		return;

	th = bpf_dynptr_slice(&ptr, iph->ihl << 2, (void *)&_th, sizeof(_th));
	if (!th)
		return;

	metrics->tcp4_pkt_count++;

	struct flow_t flow = {
		.protocol = iph->protocol,
		.ipv4_saddr = iph->saddr,
		.ipv4_daddr = iph->daddr,
		.dport = th->dest,
		.sport = th->source,
	};

	//__u32 key = 0;
	//struct count_map_t *inner_map;
	//inner_map = bpf_map_lookup_elem(&counter_map_of_map, &key);
	//if (inner_map == NULL) {
	//	metrics->err_inner_map_not_found++;
	//	return;
	//}

	struct flow_stats_t *stat;
	stat = bpf_map_lookup_elem(&count_map, &flow);
	if (stat == NULL) {
		metrics->flow_not_found++;
		return;
	}

	__sync_fetch_and_add(&stat->pkts, 1);
	__sync_fetch_and_add(&stat->bytes, iph->tot_len);
}

SEC("netfilter")
int nf_count(struct bpf_nf_ctx *ctx)
{
	__nf_count(ctx);
	return NF_ACCEPT;
}
