
/**
 * 队列映射
 * 
 * 队列映射使用先进先出 (FIFO) 存储映射元素。映射类型被定义为 BPF_MAP_TYPE_QUEUE
 * 。 FIFO 意味着当从映射中获取一个元素，返回是映射中存在时间最长的元素。 bpf
 * 映射的帮助函数以一种可预测的方式来操作这个数据结构。使用 bpf_map_lookup_elem
 * 时，这个映射始终会寻找映射中最旧的元素。使用 bpf_map_update_elem
 * 时，映射会将元素添加到队列末尾，因此，我们需要先读取映射中其余元素，才能获取此元素。同样，你也
 * 可以使用帮助函数
 * bpf_map_lookup_and_delete来获取较旧的元素，然后保持原子性，将其从映射中删除。此映射不支持帮助函数
 * bpf_map_delete_elem 和 bpf_map_get_next_key。如果使用它们会失败， errno 变量设置为 EINVAL。
 *
 * 关于这种类型映射，你还需要记住如下事情:它们不能使用映射的键进行查找。初始化映射时，键的大小必须为零。
 * 元素写入映射时，键必须为空值。
 * 
 * 让我们看一个如何使用这种类型映射的示例:
 */


#include <linux/bpf.h>
#include <linux/pkt_cls.h>
// #include <bpf/bpf_helpers.h>
#include <bpf/bpf.h>
#include <stdio.h>

// gcc 25队列映射.c -o 25队列映射 -lbpf
// 注释的都是书上给的代码

/*
// 新版本的libbpf不再支持此方式创建映射
struct bpf_map_def SEC("maps") queue_map = {
  .type = BPF_MAP_TYPE_QUEUE,
  .key_size = 0,
  .value_size = sizeof(int),
  .max_entries = 100,
  .map_flags = 0,
};
*/

// 在此映射中插入几个元素，然后以插入的顺序获取它们
int main(void) {
  int fd;
  fd = bpf_create_map(BPF_MAP_TYPE_QUEUE, 0, sizeof(int), 100, 0);

  int i;
  for (i = 0; i < 5; i++) {
    // bpf_map_update_elem(&queue_map, NULL, &i, BPF_ANY);
    bpf_map_update_elem(fd, NULL, &i, BPF_ANY);
  }

  int value;
  for (i = 0; i < 5; i++) {
    // bpf_map_lookup_and_delete(&queue_map, NULL, &value);
    bpf_map_lookup_and_delete_elem(fd, NULL, &value);
    printf("Value read from the map:%d'\n", value);
  }
}

/*
 * 该程序打印以下内容:
 * Value read from the map: '0' 
 * Value read from the map: '1' 
 * Value read from the map: '2' 
 * Value read from the map: '3' 
 * Value read from the map: '4'
 */

/*
下面代码是gpt修改后的，将main取消掉了
gpt给的编译方式：clang -O2 -target bpf -c 25队列映射.c -o 25队列映射.o
SEC("prog")
int my_prog(void) {
  int i;
  for (i = 0; i < 5; i++) bpf_map_update_elem(&queue_map, NULL, &i, BPF_ANY);

  int value;
  for (i = 0; i < 5; i++) {
    bpf_map_lookup_and_delete(&queue_map, NULL, &value);
    // 输出到 BPF 跟踪日志，因为 eBPF 无法直接使用 printf
    bpf_trace_printk("Value read from the map: %d\n", value);
  }

  return 0;
}
*/