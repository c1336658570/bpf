#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <unistd.h>

/*
 * cgroup数组映射
 * 
 * 这种类型的映射保存对cgroup的引用。映射类型定义为BPF_MAP_TYPE_CGROUP_ARRAY。
 * 从本质上讲，它们的行为类似于BPF_MAP_TYPE_PROG_ARRAY，只是它们存储指向cgroup的文件描述符。
 * 
 * 当你要在BPF映射之间共享cgroup引用控制流量、调试和测试时，这种类型映射非常有用。
 */

// 映射定义
struct bpf_map_def SEC("ma ps ") cgroups_map = {
  .type = BPF_MAP_TYPE_CGROUP_ARRAY,
  .key_size = sizeof(uint32_t),
  .value_size = sizeof(uint32_t),
  .max_entries = 1,
};

/*
 * 可以通过打开包含cgroup文件，获得cgroup内进程的文件描述符。我们
 * 将打开控制Docker容器的基本CPU共享的cgroup，并将cgroup内进程的文
 * 件描述符保存到映射中:
 * 
 * 通过打开包含cgroup文件：cgroup（控制组）是Linux内核的一个特性，它用于限制、账户和隔离进程组。
 * 这里指的是打开与cgroup相关的文件。
 * 
 * 获得cgroup内进程的文件描述符：cgroup在文件系统中有相应的文件，这些文件包含了有关cgroup内进程的信息。
 * 通过打开这些文件，可以获取文件描述符，使得我们可以读取或写入这些文件，从而与cgroup中的进程进行交互。
 * 
 * 打开控制Docker容器的基本CPU共享的cgroup：Docker使用cgroup来限制和管理容器的资源。
 * 在这里，描述了打开用于控制Docker容器CPU共享的cgroup文件。
 * 
 * 将cgroup内进程的文件描述符保存到映射中：使用BPF（Berkeley Packet Filter）或类似的技术，
 * 可以创建一个映射（map），将cgroup内进程的文件描述符关联到特定的键或索引。这样，通过查找映射，
 * 可以快速访问与每个进程相关联的文件描述符。
 */
int cgroup_fd, key = 0;
cgroup_fd = open("/sys/fs/cgroup/cpu/docker/cpu.shares", O_RDONLY);
bpf_update_elem(&cgroups_map, &key, &cgroup_fd, 0);