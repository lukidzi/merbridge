/*
Copyright © 2022 Merbridge Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "headers/helpers.h"
#include "headers/mesh.h"

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ORIGIN_FLAG 0b00001000
#define ETH_P_IP 0x0800
#define ETH_HLEN 14

// local_pods stores Pods' ips in current node.
// which can be set by controller.
// only contains injected pods.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __uint(key_size, sizeof(__u32) * 4);
    __uint(value_size, sizeof(struct pod_config));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} local_pod_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __uint(key_size, sizeof(struct pair));
    __uint(value_size, sizeof(struct origin_info));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pair_orig_dst SEC(".maps");

SEC("classifier") int mb_tc_ingress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_SHOT;
    }

    __u32 src_ip[4];
    __u32 dst_ip[4];
    struct tcphdr *tcph;
    __u32 csum_off;
    __u32 dport_off;

    switch (bpf_htons(eth->h_proto)) {
#if ENABLE_IPV4
    case ETH_P_IP: {
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if ((void *)(iph + 1) > data_end) {
            return TC_ACT_SHOT;
        }
        if (iph->protocol == IPPROTO_IPIP) {
            iph = ((void *)iph + iph->ihl * 4);
            if ((void *)(iph + 1) > data_end) {
                return TC_ACT_OK;
            }
        }
        if (iph->protocol != IPPROTO_TCP) {
            return TC_ACT_OK;
        }
        set_ipv4(src_ip, iph->saddr);
        set_ipv4(dst_ip, iph->daddr);
        tcph = (struct tcphdr *)(iph + 1);
        csum_off =
            ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check);
        dport_off =
            ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest);
        break;
    }
#endif
#if ENABLE_IPV6
    case ETH_P_IPV6: {
        struct ipv6hdr *iph = (struct ipv6hdr *)(eth + 1);
        if ((void *)(iph + 1) > data_end) {
            return TC_ACT_SHOT;
        }
        if (iph->nexthdr != IPPROTO_TCP) {
            return TC_ACT_OK;
        }
        set_ipv6(src_ip, iph->saddr.in6_u.u6_addr32);
        set_ipv6(dst_ip, iph->daddr.in6_u.u6_addr32);
        tcph = (struct tcphdr *)(iph + 1);
        csum_off =
            ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check);
        dport_off =
            ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, dest);
        break;
    }
#endif
    default:
        return TC_ACT_OK;
    }

    if ((void *)(tcph + 1) > data_end) {
        return TC_ACT_SHOT;
    }
    __u16 in_port = bpf_htons(IN_REDIRECT_PORT);
    if (tcph->syn && !tcph->ack) {
        // first packet
        if (tcph->dest == in_port) {
            // same node, already rewrite dest port by connect.
            // bypass.
            debugf("tc <  : already rewritten");
            return TC_ACT_OK;
        }
        // ingress without mb_connect
        struct pod_config *pod = bpf_map_lookup_elem(&local_pod_ips, dst_ip);
        if (!pod) {
            // dest ip is not on this node or not injected sidecar.
            debugf("tc <  : pod not found, bypassed");
            return TC_ACT_OK;
        }
        if (bpf_htons(tcph->dest) == pod->status_port) {
            return TC_ACT_OK;
        }
        int exclude = 0;
        IS_EXCLUDE_PORT(pod->exclude_in_ports, tcph->dest, &exclude);
        if (exclude) {
            debugf("tc <  : ignored dest port by exclude_in_ports, ip: "
                   "%pI4/%pI6c, port: %d",
                   &dst_ip[3], dst_ip, bpf_htons(tcph->dest));
            return TC_ACT_OK;
        }
        int include = 0;
        IS_INCLUDE_PORT(pod->include_in_ports, tcph->dest, &include);
        if (!include) {
            debugf("tc <  : ignored dest port by include_in_ports, ip: "
                   "%pI4/%pI6c, port: %d",
                   &dst_ip[3], dst_ip, bpf_htons(tcph->dest));
            return TC_ACT_OK;
        }

        // like from 10.0.0.1:23456 => 172.31.0.123:80
        // we will rewrite the dest port from 80 to 15006
        // which will be: 10.0.0.1:23456 => 172.31.0.123:15006
        struct pair p;
        memset(&p, 0, sizeof(p));
        set_ipv6(p.sip, src_ip);
        set_ipv6(p.dip, dst_ip);
        p.sport = tcph->source;
        p.dport = in_port;

        __u16 dst_port = tcph->dest;
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        set_ipv6(origin.ip, dst_ip);
        origin.port = dst_port;
        origin.flags = TC_ORIGIN_FLAG;
        bpf_map_update_elem(&pair_orig_dst, &p, &origin, BPF_NOEXIST);

        bpf_l4_csum_replace(skb, csum_off, dst_port, in_port, sizeof(dst_port));
        bpf_skb_store_bytes(skb, dport_off, &in_port, sizeof(in_port), 0);
        debugf("tc <  : first rewritten");
    } else {
        // request
        struct pair p;
        memset(&p, 0, sizeof(p));
        set_ipv6(p.sip, src_ip);
        set_ipv6(p.dip, dst_ip);
        p.sport = tcph->source;
        p.dport = in_port;
        struct origin_info *origin = bpf_map_lookup_elem(&pair_orig_dst, &p);
        if (!origin) {
            // not exists
            // char srcip[16];
            // ipstr(src_ip, srcip);
            // char dip[16];
            // ipstr(dst_ip, dip);
            // debugf("tc <  : request origin not found %s -> %s", srcip, dip);
            // debugf("tc <  : request origin not found port %d -> %d",
            //        bpf_htons(tcph->source), bpf_htons(tcph->dest));
            debugf("tc <  : no origin");
            return TC_ACT_OK;
        }
        if (!(origin->flags & TC_ORIGIN_FLAG)) {
            // not tc origin
            debugf("tc <  : no tc origin flag");
            return TC_ACT_OK;
        }
        __u16 dst_port = tcph->dest;
        bpf_l4_csum_replace(skb, csum_off, dst_port, in_port, sizeof(dst_port));
        bpf_skb_store_bytes(skb, dport_off, &in_port, sizeof(in_port), 0);
        debugf("tc <  : rewritten");
    }
    return TC_ACT_OK;
}

SEC("classifier") int mb_tc_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_SHOT;
    }

    __u32 src_ip[4];
    __u32 dst_ip[4];
    struct tcphdr *tcph;
    __u32 csum_off;
    __u32 sport_off;

    switch (bpf_htons(eth->h_proto)) {
#if ENABLE_IPV4
    case ETH_P_IP: {
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if ((void *)(iph + 1) > data_end) {
            return TC_ACT_SHOT;
        }
        if (iph->protocol == IPPROTO_IPIP) {
            iph = ((void *)iph + iph->ihl * 4);
            if ((void *)(iph + 1) > data_end) {
                return TC_ACT_OK;
            }
        }
        if (iph->protocol != IPPROTO_TCP) {
            return TC_ACT_OK;
        }
        set_ipv4(src_ip, iph->saddr);
        set_ipv4(dst_ip, iph->daddr);
        tcph = (struct tcphdr *)(iph + 1);
        csum_off =
            ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check);
        sport_off =
            ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source);
        break;
    }
#endif
#if ENABLE_IPV6
    case ETH_P_IPV6: {
        struct ipv6hdr *iph = (struct ipv6hdr *)(eth + 1);
        if ((void *)(iph + 1) > data_end) {
            return TC_ACT_SHOT;
        }
        if (iph->nexthdr != IPPROTO_TCP) {
            return TC_ACT_OK;
        }
        set_ipv6(src_ip, iph->saddr.in6_u.u6_addr32);
        set_ipv6(dst_ip, iph->daddr.in6_u.u6_addr32);
        tcph = (struct tcphdr *)(iph + 1);
        csum_off =
            ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check);
        sport_off =
            ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, source);
        break;
    }
#endif
    default:
        return TC_ACT_OK;
    }

    if ((void *)(tcph + 1) > data_end) {
        return TC_ACT_SHOT;
    }
    __u16 in_port = bpf_htons(IN_REDIRECT_PORT);
    if (tcph->source != in_port) {
        debugf("tc  > : no need to rewrite src port, bypassed");
        return TC_ACT_OK;
    }
    // response
    // like from 172.31.0.123:15006 => 10.0.0.1:23456
    // to avoid the client drop packet, we must reset the source port from
    // 15006 to 80.
    struct pair p;
    memset(&p, 0, sizeof(p));
    __u32 pre_dst_ip = dst_ip[3];
    set_ipv6(p.dip, src_ip);
    set_ipv6(p.sip, dst_ip);
    p.dport = tcph->source;
    p.sport = tcph->dest;
    struct origin_info *origin = bpf_map_lookup_elem(&pair_orig_dst, &p);
    if (!origin) {
        // not exists
        debugf("tc  > : resp origin not found");
        return TC_ACT_OK;
    }
    if (!(origin->flags & TC_ORIGIN_FLAG)) {
        // not tc origin
        printk("tc  > : resp origin flags %x error", origin->flags);
        return TC_ACT_OK;
    }
    if (tcph->fin && tcph->ack) {
        // todo delete key
        debugf("tc  > : origin deleted");
        bpf_map_delete_elem(&pair_orig_dst, &p);
    }
    __u16 src_port = origin->port;
    bpf_l4_csum_replace(skb, csum_off, in_port, src_port, sizeof(src_port));
    bpf_skb_store_bytes(skb, sport_off, &src_port, sizeof(src_port), 0);
    debugf("tc  > : rewritten");
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
