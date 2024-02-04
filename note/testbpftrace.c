// 测试uprobe
// sudo bpftrace -e 'uprobe:/home/cccmmf/bpf/note/testbpftrace:add { printf("ID:%d\n", pid); } '
// sudo bpftrace -e 'uprobe:/home/cccmmf/bpf/note/testbpftrace:add { @argument1 = arg0; @argument2 = arg1; } '
// sudo bpftrace -e 'uprobe:/home/cccmmf/bpf/note/testbpftrace:add { @argument1 = arg0; @argument2 = arg1; printf("arg1 = %d, arg2 = %d\n", @argument1, @argument2);} 

#include <stdio.h>

int add (int a, int b) {
  return a + b;
}

int main(void) {
  add (10, 20);

  return 0;
}