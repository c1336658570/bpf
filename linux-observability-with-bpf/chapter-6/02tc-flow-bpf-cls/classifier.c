// clang  -g -c -O2 -target bpf -c classifier.c -o classifier.o
// 由tc加载

/*
 * 流量控制返回码
 * 
 * 来自man 8 TC-BPF :
 * TC_ACT_OK (0)终止数据包处理流程，允许处理数据包。
 * TC_ACT_SHOT(2)终止数据包处理流程，丢弃数据包。
 * TC_ACT_UNSPEC(-1)使用tc配置的默认操作，类似于从一个分类器返回-1。
 * TC_ACT_PIPE(3)如果有下一个动作，迭代到下一个动作。
 * TC_ACT_RECLASSIFY(1)终止数据包处理流程，从头开始分类。
 * 其他是未指定的返回码
 */

#pragma clang diagnostic ignored "-Wcompare-distinct-pointer-types"

#include <bits/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>


#define SEC(NAME) __attribute__((section(NAME), used))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __bpf_htons(x) __builtin_bswap16(x)
#define __bpf_constant_htons(x) ___constant_swab16(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __bpf_htons(x) (x)
#define __bpf_constant_htons(x) (x)
#else
#error "Fix your compiler's __BYTE_ORDER__?!"
#endif

#define bpf_htons(x) \
  (__builtin_constant_p(x) ? __bpf_constant_htons(x) : __bpf_htons(x))

static int (*bpf_trace_printk)(const char *fmt, int fmt_size,
                               ...) = (void *)BPF_FUNC_trace_printk;

#define trace_printk(fmt, ...)                                                 \
  do {                                                                         \
    char _fmt[] = fmt;                                                         \
    bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__);                       \
  } while (0)

unsigned long long load_byte(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.byte");

struct http_payload {
  int method;
};

static inline int is_http(struct __sk_buff *skb, __u64 nh_off);

typedef __uint8_t uint8_t;
typedef __uint16_t uint16_t;
typedef __uint32_t uint32_t;
typedef __uint64_t uint64_t;

// 编写分类器
// 分类器的"main"入口函数是classification函数。该函数使用SEC("classifier")来注释，以便tc知道这是要使用的分类器。
SEC("classifier")
static inline int classification(struct __sk_buff *skb) {
  // 从skb中提取一些信息。
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;   // data中包含当前数据包的所有数据及其所有协议的详细信息
  struct ethhdr *eth = data;              // 为了让程序知道这些信息的内容，我们需要将其强制转换为以太网帧(在本例中为eth变量)。

  __u16 h_proto;
  __u64 nh_off = 0;
  nh_off = sizeof(*eth);

  // 为了满足静态验证器的要求，我们需要检查数据，该数据加上eth指针的大小不超过data_end的大小
  if (data + nh_off > data_end) {
    return TC_ACT_OK;
  }

  // 从*eth的h_proto成员中获取协议类型
  h_proto = eth->h_proto;

  // 使用bpf_htons函数将其进行主机序转换，检查它是否等于IPv4协议
  if (h_proto == bpf_htons(ETH_P_IP)) {   // 0x0800是IP，0x0860是ARP
    if (is_http(skb, nh_off) == 1) {    // 检查是否是HTTP
      trace_printk("Yes! It is HTTP!\n");
    }
  }

  return TC_ACT_OK;
}

// is_http函数类似于分类器函数，is_http函数是从skb开始根据已知的IPv4协议数据的起始偏移量，以此判断数据包是否是HTTP。
// 是http返回1,不是返回0
static inline int is_http(struct __sk_buff *skb, __u64 nh_off) {
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  struct iphdr *iph = data + nh_off;    // ip头

  /*
  // 书上代码这里是错误的，因为只检查了iph+1，只判断了ip头是否有一个字节，但是下面使用了protocol
  if (iph + 1 > data_end) {
    return 0;
  }
  */
  if ((void*)iph + sizeof(struct iphdr) > data_end) {
    return 0;
  }

  if (iph->protocol != IPPROTO_TCP) {   // 判断是否是TCP数据包
    return 0;
  }
  __u32 tcp_hlen = 0;
  __u32 ip_hlen = 0;
  __u32 poffset = 0;
  __u32 plength = 0;
  __u32 ip_total_length = iph->tot_len;   // ip数据包总长度

  ip_hlen = iph->ihl << 2;                // ip头部长度

  if (ip_hlen < sizeof(*iph)) {
    return 0;
  }

  struct tcphdr *tcph = data + nh_off + sizeof(*iph);   // 获取tcp头

  if (tcph + 1 > data_end) {    // 检查tcp数据包是否包含http数据包
    return 0;
  }

  tcp_hlen = tcph->doff << 2;   // 获取tcp数据包长度

  poffset = ETH_HLEN + ip_hlen + tcp_hlen;    // 获取http头偏移
  plength = ip_total_length - ip_hlen - tcp_hlen;
  // 检查字节数组是否是一个HTTP序列。
  if (plength >= 7) {
    unsigned long p[7];
    int i = 0;
    for (i = 0; i < 7; i++) {

      p[i] = load_byte(skb, poffset + i);
    }
    int *value;
    if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
      return 1;
    }
  }

  return 0;
}

char _license[] SEC("license") = "GPL";
