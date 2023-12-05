#include <linux/types.h>
#include <stdio.h>
#include <stdint.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <errno.h>
#include <string.h>

/**
 * LPM Tire映射是使用最长前缀匹配(LPM)算来来查找映射元素。LPM是一种使用最长查找项选择树中元素的算法。
 * 此算法用于路由器和其他设备的流量转发表上，用来匹配IP地址到特定的路由表项上。映射类型被定义为BPF_MAP_TYPE_LPM_TRIE。
 * 
 * 该映射要求键大小为8的倍数，范围从8到2048。如果你不想实现自己的键，内核会提供一个结构bpf_lpm_trie_key，可以使用这些键。
 * 
 * 下一个示例中，我们向映射添加三条转发路由，井匹配IP地址到正确路由上。
*/

// 创建映射
struct bpf_map_def SEC("maps") routing_map = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = 8,
  .value_size = sizeof(uint64_t),
  .max_entries = 10000,
  .map_flags = BPF_F_NO_PREALLOC,
};

int main(void) {
  // 将以下三条转发路由写入此映射192.168.0.0/16、192.168.0.0/24和192.168.1.0/24
  uint64_t value_1 = 1;
  struct bpf_lpm_trie_key route_1 = {.data = {192, 168, 0, 0}, .prefixlen = 16};
  uint64_t value_2 = 2;
  struct bpf_lpm_trie_key route_2 = {.data = {192, 168, 0, 0}, .prefixlen = 24};
  uint64_t value_3 = 3;
  struct bpf_lpm_trie_key route_3 = {.data = {192, 168, 1, 0}, .prefixlen = 24};

  bpf_map_update_elem(&routing_map, &route_1, &value_1, BPF_ANY);
  bpf_map_update_elem(&routing_map, &route_2, &value_2, BPF_ANY);
  bpf_map_update_elem(&routing_map, &route_3, &value_3, BPF_ANY);

  // 使用相同的键结构来查找路由表项匹配IP地址192.168.1.1/32 
  uint64_t result;
  struct bpf_lpm_trie_key lookup = {.data = {192, 168, 1, 1}, .prefixlen = 32};
  /*
  下面这个函数已经被改了
  man手册现在的函数：void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)
  int ret = bpf_map_lookup_e1em(&routing_map, &lookup, &result);
  if (ret == 0) {
    printf("Va1ue read from the map: '%d'\n", result);
  }
  */
  uint64_t *res = bpf_map_lookup_elem(&lookup, &lookup);
  if (res == NULL) {
    printf("error, %s\n", strerror(errno));
  } else {
    printf("res = %ld\n", *res);
  }

  return 0;
}