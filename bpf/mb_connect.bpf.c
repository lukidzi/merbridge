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

#if ENABLE_IPV4
static __u32 outip = 1;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct origin_info));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} cookie_orig_dst SEC(".maps");

// BPF_MAP_TYPE_LRU_HASH - an LRU hash will
// automatically evict the least recently used
// entries when the hash table reaches capacity
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u32) * 4);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} netns_pod_ips SEC(".maps");

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

// process_ip stores envoy's ip address.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} process_ip SEC(".maps");

static inline int udp_connect4(struct bpf_sock_addr *ctx)
{
#if MESH != ISTIO && MESH != KUMA
    // only works on istio and kuma
    return 1;
#endif
    if (bpf_htons(ctx->user_port) != 53) {
        return 1;
    }
    if (!(is_port_listen_current_ns(ctx, ip_zero, OUT_REDIRECT_PORT) &&
          is_port_listen_udp_current_ns(ctx, localhost, DNS_CAPTURE_PORT))) {
        // this query is not from mesh injected pod, or DNS CAPTURE not enabled.
        // we do nothing.
        return 1;
    }

    __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid != SIDECAR_USER_ID) {
        // needs rewrite
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        set_ipv4(origin.ip, ctx->user_ip4);
        origin.port = ctx->user_port;
        // save original dst
        __u64 cookie = bpf_get_socket_cookie(ctx);
        if (bpf_map_update_elem(&cookie_orig_dst, &cookie, &origin, BPF_ANY)) {
            printk("conn4 : update origin cookie failed: %d", cookie);
        }
        ctx->user_port = bpf_htons(DNS_CAPTURE_PORT);
        ctx->user_ip4 = localhost;
    }
    return 1;
}

static inline int tcp_connect4(struct bpf_sock_addr *ctx)
{
    // todo(kebe7jun) more reliable way to verify,
    if (!is_port_listen_current_ns(ctx, ip_zero, OUT_REDIRECT_PORT)) {
        // bypass normal traffic.
        // we only deal pod's traffic managed by istio or kuma.
        return 1;
    }

    __u32 curr_pod_ip = 0;
    __u32 _curr_pod_ip[4];

    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    __u64 netns_inum = BPF_CORE_READ(t, nsproxy, net_ns, ns.inum);

    __u32 *ip = bpf_map_lookup_elem(&netns_pod_ips, &netns_inum);
    if (!ip) {
        debugf("conn4 : geting ip for netns failed: netns_inum: %u",
               netns_inum);
    } else {
        set_ipv6(_curr_pod_ip, ip); // network order
        curr_pod_ip = get_ipv4(ip);
        debugf("conn4 : got ip for netns: netns_inum: %u, ip: %pI4", netns_inum,
               &curr_pod_ip);
    }

    __u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    __u32 dst_ip = ctx->user_ip4;
    debugf("conn4 : %u %pI4 %pI4: connect", uid, &curr_pod_ip, &dst_ip);

    if (uid != SIDECAR_USER_ID) {
        if ((dst_ip & 0xff) == 0x7f) {
            // app call local, bypass.
            return 1;
        }
        __u64 cookie = bpf_get_socket_cookie(ctx);
        // app call others
        debugf(
            "conn4 : call from user container: cookie: %d, ip: %pI4, port: %d",
            cookie, &dst_ip, bpf_htons(ctx->user_port));

        // we need redirect it to envoy.
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        set_ipv4(origin.ip, dst_ip);
        origin.port = ctx->user_port;
        origin.flags = 1;
        if (bpf_map_update_elem(&cookie_orig_dst, &cookie, &origin, BPF_ANY)) {
            printk("conn4 : write cookie_orig_dst failed");
            return 0;
        }
        if (curr_pod_ip) {
            struct pod_config *pod =
                bpf_map_lookup_elem(&local_pod_ips, _curr_pod_ip);
            if (pod) {
                int exclude = 0;
                IS_EXCLUDE_PORT(pod->exclude_out_ports, ctx->user_port,
                                &exclude);
                if (exclude) {
                    debugf(
                        "conn4 : ignored dest port by exclude_out_ports, ip: "
                        "%pI4, port: %d",
                        &curr_pod_ip, bpf_htons(ctx->user_port));
                    return 1;
                }
                IS_EXCLUDE_IPRANGES(pod->exclude_out_ranges, dst_ip, &exclude);
                debugf("conn4 : exclude ipranges: %x, exclude: %d",
                       pod->exclude_out_ranges[0].net, exclude);
                if (exclude) {
                    debugf("conn4 : ignored dest ranges by exclude_out_ranges, "
                           "ip: %pI4",
                           &dst_ip);
                    return 1;
                }
                int include = 0;
                IS_INCLUDE_PORT(pod->include_out_ports, ctx->user_port,
                                &include);
                if (!include) {
                    debugf("conn4 : dest port %d not in pod(%pI4)'s "
                           "include_out_ports, ignored.",
                           bpf_htons(ctx->user_port), &curr_pod_ip);
                    return 1;
                }

                IS_INCLUDE_IPRANGES(pod->include_out_ranges, dst_ip, &include);
                if (!include) {
                    debugf("conn4 : dest %pI4 not in pod(%pI4)'s "
                           "include_out_ranges, ignored.",
                           &dst_ip, &curr_pod_ip);
                    return 1;
                }
            } else {
                debugf("conn4 : current pod ip found(%pI4), but can not find "
                       "pod_info from local_pod_ips",
                       &curr_pod_ip);
            }
            // todo port or ipranges ignore.
            // if we can get the pod ip, we use bind func to bind the pod's ip
            // as the source ip to avoid quaternions conflict of different pods.
            struct sockaddr_in addr;
            addr.sin_addr.s_addr = curr_pod_ip;
            addr.sin_port = 0;
            addr.sin_family = 2;
            if (bpf_bind(ctx, (struct sockaddr *)&addr,
                         sizeof(struct sockaddr_in))) {
                printk("bind %pI4 error", &curr_pod_ip);
            }
            ctx->user_ip4 = localhost;
        } else {
            // if we can not get the pod ip, we rewrite the dest address.
            // The reason we try the IP of the 127.128.0.0/20 segment instead of
            // using 127.0.0.1 directly is to avoid conflicts between the
            // quaternions of different Pods when the quaternions are
            // subsequently processed.
            ctx->user_ip4 = bpf_htonl(0x7f800000 | (outip++));
            if (outip >> 20) {
                outip = 1;
            }
        }
        ctx->user_port = bpf_htons(OUT_REDIRECT_PORT);
    } else {
        // from envoy to others
        __u32 _dst_ip[4];
        set_ipv4(_dst_ip, dst_ip);
        struct pod_config *pod = bpf_map_lookup_elem(&local_pod_ips, _dst_ip);
        if (!pod) {
            // dst ip is not in this node, bypass
            debugf("conn4 : dest ip: %pI4 not in this node, bypass", &dst_ip);
            return 1;
        }

        // dst ip is in this node, but not the current pod,
        // it is envoy to envoy connecting.
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        set_ipv4(origin.ip, dst_ip);
        origin.port = ctx->user_port;

        if (curr_pod_ip) {
            if (curr_pod_ip != dst_ip) {
                // call other pod, need redirect port.
                int exclude = 0;
                IS_EXCLUDE_PORT(pod->exclude_in_ports, ctx->user_port,
                                &exclude);
                if (exclude) {
                    debugf("conn4 : ignored dest port by exclude_in_ports, ip: "
                           "%pI4, port: %d",
                           &dst_ip, bpf_htons(ctx->user_port));
                    return 1;
                }
                int include = 0;
                IS_INCLUDE_PORT(pod->include_in_ports, ctx->user_port,
                                &include);
                if (!include) {
                    debugf("conn4 : ignored dest port by include_in_ports, ip: "
                           "%pI4, port: %d",
                           &dst_ip, bpf_htons(ctx->user_port));
                    return 1;
                }
                ctx->user_port = bpf_htons(IN_REDIRECT_PORT);
            }
            origin.flags |= 1;
        } else {
            // can not get current pod ip, we use the lagecy mode.

            // u64 bpf_get_current_pid_tgid(void)
            // Return A 64-bit integer containing the current tgid and
            //                 pid, and created as such: current_task->tgid <<
            //                 32
            //                | current_task->pid.
            // pid may be thread id, we should use tgid
            __u32 pid = bpf_get_current_pid_tgid() >> 32; // tgid
            void *curr_ip = bpf_map_lookup_elem(&process_ip, &pid);
            if (curr_ip) {
                // envoy to other envoy
                if (*(__u32 *)curr_ip != dst_ip) {
                    debugf("conn4 : enovy to other, rewrite dst port from %d "
                           "to %d",
                           ctx->user_port, IN_REDIRECT_PORT);
                    ctx->user_port = bpf_htons(IN_REDIRECT_PORT);
                }
                origin.flags |= 1;
                // envoy to app, no rewrite
            } else {
                origin.flags = 0;
                origin.pid = pid;
                // envoy to envoy
                // try redirect to 15006
                // but it may cause error if it is envoy call self pod,
                // in this case, we can read src and dst ip in sockops,
                // if src is equals dst, it means envoy call self pod,
                // we should reject this traffic in sockops,
                // envoy will create a new connection to self pod.
                ctx->user_port = bpf_htons(IN_REDIRECT_PORT);
            }
        }
        __u64 cookie = bpf_get_socket_cookie(ctx);
        debugf("conn4 : call from sidecar container: cookie: %d, ip: %pI4, "
               "port: %d",
               cookie, &dst_ip, bpf_htons(ctx->user_port));
        if (bpf_map_update_elem(&cookie_orig_dst, &cookie, &origin,
                                BPF_NOEXIST)) {
            printk("conn4 : update cookie origin failed");
            return 0;
        }
    }

    return 1;
}

SEC("cgroup/connect4") int mb_sock_connect4(struct bpf_sock_addr *ctx)
{
    switch (ctx->protocol) {
    case IPPROTO_TCP:
        return tcp_connect4(ctx);
    case IPPROTO_UDP:
        return udp_connect4(ctx);
    default:
        return 1;
    }
}
#endif

#if ENABLE_IPV6
static inline int udp_connect6(struct bpf_sock_addr *ctx)
{
#if MESH != ISTIO && MESH != KUMA
    // only works on istio and kuma
    return 1;
#endif
    if (bpf_htons(ctx->user_port) != 53) {
        return 1;
    }
    if (!(is_port_listen_current_ns6(ctx, ip_zero6, OUT_REDIRECT_PORT) &&
          is_port_listen_udp_current_ns6(ctx, localhost6, DNS_CAPTURE_PORT))) {
        // this query is not from mesh injected pod, or DNS CAPTURE not enabled.
        // we do nothing.
        return 1;
    }

    __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid != SIDECAR_USER_ID) {
        // needs rewrite
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        set_ipv6(origin.ip, ctx->user_ip6);
        origin.port = ctx->user_port;
        // save original dst
        __u64 cookie = bpf_get_socket_cookie(ctx);
        if (bpf_map_update_elem(&cookie_orig_dst, &cookie, &origin, BPF_ANY)) {
            printk("conn6 : update origin cookie failed: %d", cookie);
        }
        ctx->user_port = bpf_htons(DNS_CAPTURE_PORT);
        set_ipv6(ctx->user_ip6, localhost6);
    }
    return 1;
}

static inline int tcp_connect6(struct bpf_sock_addr *ctx)
{
    // todo(kebe7jun) more reliable way to verify,
    if (!is_port_listen_current_ns6(ctx, ip_zero6, OUT_REDIRECT_PORT)) {
        // bypass normal traffic.
        // we only deal pod's traffic managed by istio or kuma.
        return 1;
    }

    __u32 curr_pod_ip[4];
    __u32 dst_ip[4];

    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    __u64 netns_inum = BPF_CORE_READ(t, nsproxy, net_ns, ns.inum);

    __u32 *ip = bpf_map_lookup_elem(&netns_pod_ips, &netns_inum);
    if (!ip) {
        debugf("conn6 : getting ip for netns failed: netns_inum: %u",
               netns_inum);
        return 1;
    }

    debugf("conn6 : got ip for netns: netns_inum: %u, ip: %pI6", netns_inum,
           &curr_pod_ip);

    set_ipv6(curr_pod_ip, ip);
    set_ipv6(dst_ip, ctx->user_ip6);

    __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid != SIDECAR_USER_ID) {
        if (ipv6_equal(dst_ip, localhost6)) {
            // app call local, bypass.
            return 1;
        }
        __u64 cookie = bpf_get_socket_cookie(ctx);
        // app call others
        debugf(
            "conn6 : call from user container: cookie: %d, ip: %pI6c, port: %d",
            cookie, dst_ip, bpf_htons(ctx->user_port));

        // we need redirect it to envoy.
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        set_ipv6(origin.ip, dst_ip);
        origin.port = ctx->user_port;

        if (bpf_map_update_elem(&cookie_orig_dst, &cookie, &origin, BPF_ANY)) {
            printk("conn6 : write cookie_orig_dst failed");
            return 0;
        }
        // TODO(dddddai): add support for annotations

        // if we can get the pod ip, we use bind func to bind the pod's ip
        // as the source ip to avoid quaternions conflict of different pods.
        struct sockaddr_in6 addr;
        set_ipv6(addr.sin6_addr.in6_u.u6_addr32, curr_pod_ip);
        addr.sin6_port = 0;
        addr.sin6_family = 10;
        if (bpf_bind(ctx, (struct sockaddr *)&addr,
                     sizeof(struct sockaddr_in6))) {
            printk("conn6 : bind %pI6c error", curr_pod_ip);
        }
        set_ipv6(ctx->user_ip6, localhost6);
        ctx->user_port = bpf_htons(OUT_REDIRECT_PORT);
    } else {
        // from envoy to others
        if (!bpf_map_lookup_elem(&local_pod_ips, dst_ip)) {
            // dst ip is not in this node, bypass
            debugf("conn6 : dest ip: %pI6c not in this node, bypass", dst_ip);
            return 1;
        }
        // dst ip is in this node, but not the current pod,
        // it is envoy to envoy connecting.
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        origin.port = ctx->user_port;
        set_ipv6(origin.ip, dst_ip);
        if (!ipv6_equal(dst_ip, curr_pod_ip)) {
            debugf("conn6 : enovy to other, rewrite dst port from %d to %d",
                   ctx->user_port, bpf_htons(IN_REDIRECT_PORT));
            ctx->user_port = bpf_htons(IN_REDIRECT_PORT);
        }
        __u64 cookie = bpf_get_socket_cookie(ctx);
        debugf("conn6 : call from sidecar container: cookie: %d, ip: %pI6c, "
               "port: %d",
               cookie, dst_ip, bpf_htons(ctx->user_port));
        if (bpf_map_update_elem(&cookie_orig_dst, &cookie, &origin,
                                BPF_NOEXIST)) {
            printk("conn6 : update cookie origin failed");
            return 0;
        }
    }
    return 1;
}

SEC("cgroup/connect6") int mb_sock_connect6(struct bpf_sock_addr *ctx)
{
    switch (ctx->protocol) {
    case IPPROTO_TCP:
        return tcp_connect6(ctx);
    case IPPROTO_UDP:
        return udp_connect6(ctx);
    default:
        return 1;
    }
}
#endif

char LICENSE[] SEC("license") = "GPL";
