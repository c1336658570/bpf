#include <linux/bpf.h>
#include <bpf/bpf.h>
// #include <bpf/bpf_helpers.h>
#include <stdio.h>
#include <errno.h>

/*
 * 栈映射
 * 
 * 栈映射使用后进先出 (LIFO) 在映射中存储元素。映射类型定义为
 * BPF_MAP_TYPE_STACK。LIFO
 * 意味着当从映射中获取一个元素，返回是最近添加到映射中的元素。
 *
 * bpf 映射的帮助函数也以一种可预测的方式来操作这个数据结构。使用
 * bpf_map_lookup_elem 时，映射始终会寻找映射中的最新元素。使用
 * bpf_map_update_elem
 * 时，映射始终会将元素添加到栈顶，因此，它可以被第一个获取。同时，也可以使用帮助函数
 * bpf_map_lookup_and_delete
 * 获取最新元素并保持原子性，从映射中删除元素。该映射不支持帮助函数
 * bpf_map_delete_elem和bpf_map_get_next_key。 如果使用它们会失败errno
 * 变量设置为 EINVAL
 */

/*
struct bpf_map_def SEC("maps") stack_map ={
  .type= BPF_MAP_TYPE_STACK,
  .key_size=0,
  .value_size = sizeof(int),
  .max_entries = 100,
  .map_flags=0,
};
*/

// gcc 26栈映射.c -o 26栈映射 -lbpf
// 注释的部分都是书上给的代码

int main() {
  int fd;
  fd = bpf_create_map(BPF_MAP_TYPE_STACK, 0, sizeof(int), 100, 0);

  int i;
  for (i = 0; i < 5; i++) {
    // bpf_map_update_elem(&stack_map,NULL,&i,BPF_ANY);
    bpf_map_update_elem(fd, NULL, &i, BPF_ANY);
  }

  int value;
  for (i = 0; i < 5; i++) {
    int ret = bpf_map_lookup_and_delete_elem(fd, NULL, &value);
    // bpf_map_lookup_and_delete(&stack_map,NULL, &value);
    printf("Value read from the map:%d, ret = %d'\n", value, ret);
  }
    
  // 如果从映射中取出一个新元素，bpf_map_lookup_and_delete将返回负数，errno变量设置为ENOENT。
  // #define	ENOENT		 2
  int ret = bpf_map_lookup_and_delete_elem(fd, NULL, &value);
  printf("ret = %d, errno = %d, string = %s\n", ret , errno, strerror(errno));
  return 0;
}

/*
 * 该程序打印以下内容:
 * Value read from the map: '4'
 * Value read from the map: '3'
 * Value read from the map: '2'
 * Value read from the map: '1'
 * Value read from the map: '0'
 */