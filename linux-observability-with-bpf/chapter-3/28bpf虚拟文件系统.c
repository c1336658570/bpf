#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <bpf/bpf.h>

// BPF映射文件的路径
static const char *file_path = "/sys/fs/bpf/my_array";

int main(int argc, char **argv) {
  int fd, key, value, result;

  // 通过路径获取BPF映射文件的文件描述符
  fd = bpf_obj_get(file_path);
  if (fd < 0) {
    // 处理获取文件描述符失败的情况
    printf("Failed to fetch the map: %d (%s)\n", fd, strerror(errno));
    return -1;
  }

  // 要查询的键
  key = 1;
  // 从BPF映射中查询键对应的值
  // 内核中运行的BPF程序对应的函数是这个void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)
  result = bpf_map_lookup_elem(fd, &key, &value);
  // 不知道为什么查询失败返回0，按理来说失败返回负数。
  // 如果通过bpf_map_lookup_elem读取映射元素返回负数，errno变量将被设置为错误信息。
  // 例如，如果我们试图读取之前没有插入的值，内核将返回"not found"错误信息，用ENOENT表示。
  if (result < 0) {
    // 处理查询失败的情况
    printf("Failed to read value from the map: %d (%s)\n", result, strerror(errno));
    return -1;
  }
  printf("result = %d\n", result);
  // 打印查询到的值
  printf("Value read from the map: '%d'\n", value);

  return 0;
}
