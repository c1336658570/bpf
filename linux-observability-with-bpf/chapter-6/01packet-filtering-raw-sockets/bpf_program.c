// clang -O2 -target bpf -c bpf_program.c -o bpf_program.o
// sudo ./loader bpf_program.o
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>

// 检查这个数据包的协议是TCP 、UDP或ICMP，然后在这个协议特定键的映射数组上增加其计数。

#ifndef offsetof
// 计算结构体中成员的偏移量（offset）。
#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#endif

#define SEC(NAME) __attribute__((section(NAME), used))

struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
};

static int (*bpf_map_update_elem)(struct bpf_map_def *map, void *key,
void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;

static void *(*bpf_map_lookup_elem)(struct bpf_map_def *map, void *key) =
(void *)BPF_FUNC_map_lookup_elem;

unsigned long long load_byte(void *skb, unsigned long long off) asm("llvm.bpf.load.byte");


// 创建一个键/值的映射，协议作为映射的键，数据包的数量作为映射的值。
// pkg-config --modversion libbpf              20:42:32
// 0.5.0
// 在libbpf1.0之后不支持下面这种形式，应该改为下面的下面那种形式
struct bpf_map_def SEC("maps") countmap = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(int),
  .max_entries = 256,
};


/*
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 256);
} countmap SEC(".maps");
*/

// 程序类型为BPF_PROG_TYPE_SOCKET_FILTER，这种类型的程序我们可以看到流经接口所有的数据包。
SEC("socket")
int socket_prog(struct __sk_buff *skb) {
  // 使用 load_byte 函数从 sk_buff 结构体中获取协议信息。
  int proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
  int one = 1;
  // 将协议ID作为映射的键，使用bpf_map_lookup_elem函数从映射countmap上获得当前协议的计数，
  // 以便对其进行增加计数，或当第一个数据包达到时，将这个计数设置为1。
  int *el = bpf_map_lookup_elem(&countmap, &proto);
  if (el) {
    (*el)++;
  } else {
    el = &one;
  }
  // 使用bpf_map_update_elem利用增加的计数值来更新映射。
  bpf_map_update_elem(&countmap, &proto, el, BPF_ANY);
  return 0;
}

char _license[] SEC("license") = "GPL";
