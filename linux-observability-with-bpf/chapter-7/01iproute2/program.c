// ptyhon3 -m http.server
// clang -g -c -O2 -target bpf -c program.c -o program.o    编译
// ip link set dev wlp1s0 xdp obj program.o sec mysection   加载
// ip a show wlp1s0     查看是否成功，MTU之后显示为xdpgeneric/id:1653。已使用的驱动程序为xdpgeneric，XDP程序的ID为1653
// 验证加载的程序的功能逻辑。我们可以在外部计算机上再次执行nmap，验证端口8000不再可访问:
// sudo nmap -sS 10.30.0.138
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>


#define SEC(NAME) __attribute__((section(NAME), used))  // used是即使代码中没有使用变量或函数，也不让编译器优化掉

// 声明程序主要入口点函数 myprogram
SEC("mysection")
int myprogram(struct xdp_md *ctx) {
  int ipsize = 0;
  void *data = (void *)(long)ctx->data;     // 由于data包含以太网帧，因此现在我们可以从中提取IPv4层。
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  struct iphdr *ip;

  ipsize = sizeof(*eth);
  ip = data + ipsize;
  ipsize += sizeof(struct iphdr);
  // 通过静态验证器检查。当该偏移量超出地址空间时，我们需要丢弃数据包
  if (data + ipsize > data_end) {
    return XDP_DROP;
  }

  // 该逻辑基本上为丢弃每个 TCP 数据包，同时允许除了 TCP 协议外的其他任何内容:
  if (ip->protocol == IPPROTO_TCP) {
    return XDP_DROP;
  }

  return XDP_PASS;
}
