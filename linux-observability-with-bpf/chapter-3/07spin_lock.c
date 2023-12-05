#include <linux/types.h>
#include <linux/bpf.h>
#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>

/*
 * 并发访问映射元素
 * 
 * 许多程序可以同时并发访问相同的映射。BPF引入了BPF自旋锁的概念，可以在操作映射元素时对访问的映射元素进行锁定。
 * bpf_spin_lock锁定、bpf_spin_unlock解锁。这两个帮助函数的工作原理是使用充当信号的数据结构访问包括信号的元素，
 * 当信号被锁定后，其他程序将无法访问该元素值，直至信号被解锁。同时，BPF自旋锁引入了一个新的标志，
 * 用户空间程序可以使用该标志来更改该锁的状态。该标志为BPF_F_LOCK。
 * 
 * 使用自旋锁，我们需要做的第一件事是创建要锁定访问的元素，然后为该元素添加信号:
 * struct concurrent_element {
 * struct bpf_spin_lock semaphore;
 * int count;
 * }
 * 将这个结构保存在BPF映射中，并在元素中使用信号防止对元素不可预期的访问。
 * 我们可以声明持有这些元素的映射。该映射必须使用BPF类型格式(BPF Type Format，BTF)进行注释，
 * 以便验证器知道如何解释BTF。BTF可以通过给二进制对象添加调试信息，为内核和其他工具提供更丰富的信息。
 * 因为代码将在内核中运行，我们可以使用libbpf的内核宏来注释这个并发映射:
 */

// 定义并发元素结构体
struct concurrent_element {
  struct bpf_spin_lock semaphore;   // 自旋锁，用于同步并发访问
  int count;                        // 共享计数器
};

// 定义BPF映射，用于存储并发元素，这种创建映射的方式以及无了
struct bpf_map_def SEC("maps") concurrent_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(int),
  .value_size = sizeof(struct concurrent_element),
  .max_entries = 100,
};

/// 现在采取的方式创建映射的方式
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 2);
} my_map SEC(".maps");

// 使用BPF_ANNOTATE_KV_PAIR注释BPF映射，提供键值对的信息
// 使用BPF类型格式(BPF Type Format，BTF)进行注释，以便验证器知道如何解释BTF。
// BTF可以通过给二进制对象添加调试信息，为内核和其他工具提供更丰富的信息。
// 因为代码将在内核中运行，我们可以使用libbpf的内核宏来注释这个并发映射:
BPF_ANNOTATE_KV_PAIR(concurrent_map, int, struct concurrent_element);

// BPF程序入口点，接收pt_regs上下文作为参数
int bpf_program(struct pt_regs *ctx) {
	int key = 0;
  struct concurrent_element init_value = {};
  struct concurrent_element *read_value;

  // 创建或更新映射元素，如果元素已存在则不进行更新，这个函数好像已经没了，看man手册应该用
  // long bpf_map_update_elem(struct bpf_map *map, const void *key, const void *value, u64 flags)
  bpf_map_create_elem(&concurrent_map, &key, &init_value, BPF_NOEXIST);
  // 查询映射元素的值
  read_value = bpf_map_lookup_elem(&concurrent_map, &key);

  // 使用自旋锁保护对共享计数器的更新
  // 使用这两个锁帮助函数保护这些元素防止竞争条件。映射元素的信号已被锁定，程序就可以安全地修改元素的值
  bpf_spin_lock(&read_value->semaphore);
  read_value->count += 100;           // 对共享计数器增加100
  bpf_spin_unlock(&read_value->semaphore);
}

/*
 * 在用户空间上，我们可以使用标志BPF_F_LOCK保存并发映射中元素的引用。
 * 我们可以在bpf_map_update_elem和bpf_map_lookup_elem_flags两个帮助函数中使用此标志。
 * 该标志允许你就地更新元素而无须担心数据竞争。
 * enum {
	BPF_ANY		= 0, // create new element or update existing
	BPF_NOEXIST	= 1, // create new element if it didn't exist
	BPF_EXIST	= 2, // update existing element
	BPF_F_LOCK	= 4, // spin_lock-ed map_lookup/map_update
  };
 * 
 * 对于更新哈希映射、更新数组和cgroup存储映射，BPF_F_LOCK的行为略有不同。
 * 对于后两种类型，更新是就地发生，在执行更新之前，元素必须存在于映射中。
 * 对于哈希映射，如果元素不存在，程序将锁定映射元素的存储桶，然后插入新的元素。
 */
