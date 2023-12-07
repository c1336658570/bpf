// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "sockfilter.h"

// 定义 IP 分片相关的标志位
#define IP_MF	  0x2000
#define IP_OFFSET 0x1FFF

// 定义 BPF 程序使用的许可证
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义 BPF 环形缓冲区
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 判断 IP 包是否为分片，根据 IP 头中的分片偏移和标志位
static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
	__u16 frag_off;

	// 从指定位置加载 IP 头的分片信息
	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
	frag_off = __bpf_ntohs(frag_off);
	// 判断是否是分片，根据标志位
	return frag_off & (IP_MF | IP_OFFSET);
}

// BPF Socket 程序处理函数
SEC("socket")
int socket_handler(struct __sk_buff *skb)
{
	struct so_event *e;				// 定义保存事件信息的结构体指针
	__u8 verlen;							// 定义版本号和首部长度字段
	__u16 proto;							// 定义协议字段
	__u32 nhoff = ETH_HLEN;		// 定义网络层头部偏移量，默认为以太网头部长度

	// 从指定位置加载协议字段
	bpf_skb_load_bytes(skb, 12, &proto, 2);
	proto = __bpf_ntohs(proto);
	// 检查是否为 IP 协议，如果不是则退出
	if (proto != ETH_P_IP)
		return 0;

	// 检查是否为 IP 分片，如果是则退出
	if (ip_is_fragment(skb, nhoff))
		return 0;

	// 从 BPF 环形缓冲区中预留一份空间用于存储事件信息
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	// 从指定位置加载 IP 头的协议字段
	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &e->ip_proto, 1);

	// 如果协议不是 GRE，则加载源地址和目的地址
	if (e->ip_proto != IPPROTO_GRE) {
		bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &(e->src_addr), 4);
		bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &(e->dst_addr), 4);
	}

	// 从指定位置加载 IP 头的版本号和首部长度字段
	bpf_skb_load_bytes(skb, nhoff + 0, &verlen, 1);
	// 从指定位置加载端口信息
	bpf_skb_load_bytes(skb, nhoff + ((verlen & 0xF) << 2), &(e->ports), 4);
	// 将数据包类型和接口索引信息存入事件结构体
	e->pkt_type = skb->pkt_type;
	e->ifindex = skb->ifindex;
	// 提交事件到 BPF 环形缓冲区
	bpf_ringbuf_submit(e, 0);

	// 返回数据包长度
	return skb->len;
}
