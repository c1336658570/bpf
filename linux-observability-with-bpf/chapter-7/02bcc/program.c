#define KBUILD_MODNAME "program"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>

// 运行：sudo ./loader.py

// 代码跑不了

// 丢弃TCP数据包时，统计数据包数量。

// 使用 BPF TABLE 宏声明了BPF_MAP_TYPE_PERCPU_ARRAY类型的映射。
// 该映射将包含对每个IP协议索引的数据包的计数，映射大小为256(IP协议仅包含256个)。
// 使用 BPF_MAP_TYPE_PERCPU_ARRAY 类型，因为它可以在不锁定的情况下，保证对计数器的操作在 CPU 级别上是原子的。
BPF_TABLE("percpu_array", uint32_t, long, packetcnt, 256);

// 声明我们的主函数 myprogram，该函数将 xdp_md 结构作为参数，它所作的第一件事是为以太网 IPv4 帧声明变量
int myprogram(struct xdp_md *ctx) {
  int ipsize = 0;
  void *data = (void *)(long)ctx->data;     // 设置 data 指针指向以太网帧
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  struct iphdr *ip;
  long *cnt;
  __u32 idx;

  ipsize = sizeof(*eth);
  ip = data + ipsize;   // 设置 ip 指针指向 IPv4 数据包
  ipsize += sizeof(struct iphdr);

  if (data + ipsize > data_end) {   // 检查内存地址是否超出合理范围。
    return XDP_DROP;  // 丢弃数据包
  }

  // 提取协议，并查找 packetcnt 数组以获取变量 idx 中该协议的数据包的计数值。
  idx = ip->protocol;
  cnt = packetcnt.lookup(&idx);
  if (cnt) {
    // 将计数值加一。
    *cnt += 1;
  }

  // 检查协议是否为 TCP。如果是 TCP，我们将直接丢弃该数据包;否则，我们允许该数据包
  if (ip->protocol == IPPROTO_TCP) {
    return XDP_DROP;
  }

  return XDP_PASS;
}
