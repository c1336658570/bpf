// gcc 05bpf_map_get_next_key.c -o 05bpf_map_get_next_key -lbpf
#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>

// 迭代BPF映射元素

int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

// man手册中的函数实现
int bpf_get_next_key(int fd, const void *key, void *next_key) {
  union bpf_attr attr = {
    .map_fd   = fd,
    .key      = (unsigned long long)(key),
    .next_key = (unsigned long long)(next_key),
  };

  return bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

// 在BPF程序中查找任意元素。
// BPF提供了bpf_map_get_next_key指令。该指令不像之前的帮助函数，该指令仅适用于用户空间上运行的程序。
// 三个参数，第一个参数是映射的文件描述符，第二个参数key是要查找的标识符，第三个参数next_key是映射中的下一个键。
// 如果你想知道哪个键位于键1之后，需要将1设置为lookup_key，如果映射上有与之相邻的键，BPF将其设置为next_key参数的值。
int main(int argc, char **argv) {
  int fd;

  fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(int), sizeof(int), 100, 0);
  if (fd < 0) {
    printf("Failed to create map: %d (%s)\n", fd, strerror(errno));
    return -1;
  }

  // 向映射中添加元素
  int new_key, new_value, it;
  for (it = 1; it < 6; ++it) {
    new_key = it;
    new_value = 1234 + it;
    bpf_map_update_elem(fd, &new_key, &new_value, BPF_NOEXIST);
  }

  // 如果要打印映射中的所有值，可以使用bpf_map_get_next_key和映射中不存在的查找键，这迫使BPF从开头遍历映射
  // 当bpf_map_get_next_key到达映射的尾部时，返回值为负数，errno变量设置为ENOENT。这将终止循环执行。
  int next_key, lookup_key;
  lookup_key = -1;
  while (bpf_map_get_next_key(fd, &lookup_key, &next_key) == 0) {
    printf("The next key in the map is : '%d'\n", next_key);
    lookup_key = next_key;
  }

  printf("-----------------------------------------\n");
  // 许多编程语言会在迭代映射元素前复制映射的值。这样当程序中的其他代码对映射进行修改时，可以阻止未知错误，尤其是从映射中删除元素。
  // BPF使用bpf_map_get_next_key在遍历映射前不复制映射的值。如果程序正在遍历映射元素，程序的其他代码
  // 删除了映射中的元素，当遍历程序尝试查找的下一个值是已删除元素的键时，bpf_map_get_next_key将重新开始查找
  lookup_key = -1;
  while (bpf_map_get_next_key(fd, &lookup_key, &next_key) == 0) {
    printf("The next key in the map is : '%d'\n", next_key);
    if (next_key == 2) {
      printf("Deleting key '2'\n");
      bpf_map_delete_elem(fd, &next_key);
    }
    lookup_key = next_key;
  }

  return 0;
}