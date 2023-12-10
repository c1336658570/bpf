// 运行：sudo python test_xdp.py
#define KBUILD_MODNAME "kmyprogram"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/ip.h>

// BPF_PROG_TEST_RUN可以用来测试XDP程序

// XDP程序，仅包含myprogram，以及我们python中的测试的逻辑。

int myprogram(struct xdp_md *ctx) {
  int ipsize = 0;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  struct iphdr *ip;
  struct tcphdr *th;

  ipsize = sizeof(*eth);
  ip = data + ipsize;
  ipsize += sizeof(struct iphdr);
  // 检查数据包的三层协议的偏移量和对应的变量
  if (data + ipsize > data_end) {
    return XDP_DROP;
  }

  // 检查协议是否为TCP
  if (ip->protocol == IPPROTO_TCP) {
    // 如果是TCP协议的话，总是执行XDP_DROP;
    th = (struct tcphdr *)(ip + 1);
    if ((void *)(th + 1) > data_end) {
      return XDP_DROP;
    }

    // 检查目的端口是否为9090。如果端口是9090，我们将更改以太网层目标MAC地址，然后返回XDP_TX，表示返回数据包到相同网卡上:
    if (th->dest == htons(9090)) {
      eth->h_dest[0] = 0x08;
      eth->h_dest[1] = 0x00;
      eth->h_dest[2] = 0x27;
      eth->h_dest[3] = 0xdd;
      eth->h_dest[4] = 0x38;
      eth->h_dest[5] = 0x2a;
      return XDP_TX;
    }

    return XDP_DROP;
  }

  return XDP_PASS;
}
