// gcc 06bpf_map_lookup_and_delete_elem.c -o 06bpf_map_lookup_and_delete_elem -lbpf
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

// 查找和删除元素bpf_map_lookup_and_delete_elem
// 此功能是在映射中查找指定的键井删除元素。同时，程序将该元素的值赋予一个变量。

int main(void) {
  int fd;
  fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(int), sizeof(int), 100, 0);

  int key, value, result, it, added;
  key = 1;
  value = 1234;

  added = bpf_map_update_elem(fd, &key, &value, BPF_ANY);
  if (added < 0) {
    printf("Failed to update map: %d (%s)\n", added, strerror(errno));
  } else {
    printf("Map updated with new element\n");
  }

  // 尝试两次从映射中提取相同的元素。
  // 在第一个迭代中，该代码将打印映射中元素的值。第一次迭代还将删除映射中的元素。
  // 第二次循环尝试获取元素时，该代码将会失败，errno变量设置为"No such file or directory"错误信息，用ENOENT表示。
  for (it = 0; it < 2; ++it) {
    result = bpf_map_lookup_and_delete_elem(fd, &key, &value);
    if (result == 0) {
      printf("Value read from the map : '%d'\n", value);
    } else {
      // 2是ENOENT
      printf("Failed to read value from the map : %d (%d:%s)\n", result, errno, strerror(errno));
    }
  }

  return 0;
}