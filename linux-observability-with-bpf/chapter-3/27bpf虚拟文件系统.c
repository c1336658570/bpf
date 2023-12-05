/*
 * BPF 映射的基本特征是基于文件描述符，这意味着关闭文件描述符后，映射
 * 及其所保存的所有信息都会消失。 BPF 映射的最初实现侧重于短期运行的被
 * 隔离的程序，彼此之间没有共享任何信息。在这些场景中，关闭文件描述符
 * 时清除所有数据非常有意义。但是，随着内核引入更复杂的映射和集成，开
 * 发人员意识到需要一种方法来保存映射上的信息，甚至是在程序终止和关闭
 * 映射文件描述符后一直保存信息。 Linux 内核 4 .4引入了两个新的系统调用，
 * 用以固定和获取来自虚拟文件系统的映射和 BPF 程序。当程序终止，保存到
 * 文件系统的映射和 BPF 程序将保留在内存中。本节我们将说明如何使用虚拟文件系统。
 *
 * BPF虚拟文件系统的默认目录是/sys/fs/bpf如果Linux版本系统内核不支持BPF，默认不会挂载该文件系统。
 * 可以通过mount命令挂载此文件系统:mount -t bpf /sys/fs/bpf /sys/fs/bpf
 *
 * 与其他文件系统层级结构一样 ，保存在文件系统中的持久化 BPF
 * 对象通过路径来标识。 我们可以使用任何对程序有意义的方式来组织这些路径。例如，
 * 如果想在程序之间共享带有 IP
 * 信息的特定映射，可能将其存储在/sys/fs/bpf/shared/ips中。
 * 你可以在此文件系统中保存两种类型的对象：BPF映射和完整的BPF程序。两者都是文件描述符，所以可以使用相同
 * 的接口。这些对象只能通过系统调用 bpf 来进行操作。尽管内核提供了一些
 * 高级帮助函数来帮助与它们交互，但无法通过执行系统调用打开这些文件。
 *
 * BPF_PIN_FD 是将 BPF 对象保存到文件系统的命令。命令执行成功后，该对
 * 象将在文件系统指定的路径下可见。如果命令失败，则返回负数，全局 errno
 * 变量被设置了错误码。
 *
 * BPF_OBJ_GET 是获取已固定到文件系统 BPF 对象的命令。该命令使用分配
 * 给对象的路径来加载 BPF 对象。这个命令执行成功后，将返回与对象关联
 * 的文件描述符。如果失败，返回负数，全局变量 errno 被设置了特定的错误码。
 */

// 我们将编写一个程序来创建映射，写入一些元素到映射中，并将映射保存在文件系统

#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <errno.h>

static const char *file_path = "/sys/fs/bpf/my_array";

int main(int argc, char **argv) {
  int key, value, fd, added, pinned;

  // 创建一个包含一个元素的固定大小的哈希表映射。
  fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(int), 100, 0);
  if (fd < 0) {
    printf("Failed to create map : %d (%s)\n", fd, strerror(errno));
    return -1;
  }

  key = 1, value = 1234;
  // 更新映射，添加仅有的元素。如果溢出，bpf_map_update_elem将会失败。
  added = bpf_map_update_elem(fd, &key, &value, BPF_ANY); // 可以在man bpf中找到这个函数定义
  if (added < 0) {
    printf("Failed to update map: %d (%s)\n", added, strerror(errno));
  } else {
    printf("Map updated with new element\n");
  }

  // 在/usr/include/bpf/bpf.h
  pinned = bpf_obj_pin(fd, file_path);  // 使用帮助函数bpf_obj_pin将映射保存在文件系统中。
  if (pinned < 0) {
    printf("Failed to pin map to the file system: %d (%s)\n", pinned, strerror(errno));
    return -1;
  }
  
  return 0;
}
