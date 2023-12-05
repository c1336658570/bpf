
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/types.h>
#include <stdint.h>
#include <linux/bpf.h>

// 哈希表映射
// 跟踪网络IP及其速率限制的示例程序
#define IPV4_FAMILY 1

// 声明结构化的键，用它来保留IP地址信息。
struct ip_key {
  union {
    __u32 v4_addr;
    __u8 v6_addr[16];
  };
  __u8 family;
};

// 使用该映射来跟踪速率限制。我们在该映射中将IP地址作为键。映射的值是BPF程序从特定IP地址上接收网络数据包的次数。
struct bpf_map_def SEC("maps") counters = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct ip_key),
  .value_size = sizeof(uint64_t),
  .max_entries = 100,
  .map_flags = BPF_F_NO_PREALLOC
};

// 此函数用来更新内核中counters的值
// 该函数从网络数据包中提取IP地址，井使用声明的复合键对映射进行查找。
// 这里，我们假设之前初始化counters设置为零;否则，bpf_map_lookup_elem调用将返回负数。
uint64_t update_counter(uint32_t ipv4) {
  uint64_t value;
  struct ip_key key = {};
  key.v4_addr = ipv4;
  key.family = IPV4_FAMILY;
  /*
  * 下面这个函数好像过时了
  * man 手册中的函数：
  * void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)
  * Description
  *   Perform a lookup in map for an entry associated to key.
  * Return
  *   Map  value  associated  to  key,  or NULL if no entry wasfound.
  */
  // bpf_map_lookup_elem(counters, &key, &value);
  int *val = bpf_map_lookup_elem(&counters, &key);
  // (*value) += 1;
  (*val) += 1;
}

int main(void) {
  update_counter(1234);
}