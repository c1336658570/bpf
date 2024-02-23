#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define DEBUGFS "/sys/kernel/debug/tracing/"     // 定义trace_pipe文件所在的路径
// 函数声明：从文件加载并运行BPF程序
int load_bpf_file(char *filename);

// 函数声明：从trace_pipe文件读取追踪数据
void read_trace_pipe(void);

// 从文件加载并运行BPF程序
int load_bpf_file(char *path) {
  struct bpf_object *obj;           // BPF对象
  struct bpf_program *prog;         // BPF程序
  struct bpf_link *link = NULL;     // BPF程序链接
  // 打印正在加载的BPF文件路径
  printf("%s\n", path);

  // 打开BPF对象文件
  obj = bpf_object__open_file(path, NULL);
  if (libbpf_get_error(obj)) {
    fprintf(stderr, "ERROR: opening BPF object file failed\n");
    return 0;
  }

  // 加载BPF对象文件
  if (bpf_object__load(obj)) {
    fprintf(stderr, "ERROR: loading BPF object file failed\n");
    goto cleanup;
  }

  // 查找BPF程序
  prog = bpf_object__find_program_by_name(obj, "bpf_prog");
  if (!prog) {
    printf("finding a prog in obj file failed\n");
    goto cleanup;
  }

  // 将BPF程序链接到内核
  link = bpf_program__attach(prog);
  if (libbpf_get_error(link)) {
    fprintf(stderr, "ERROR: bpf_program__attach failed\n");
    link = NULL;
    goto cleanup;
  }

  // 读取trace_pipe文件
  read_trace_pipe();

cleanup:
  // 销毁BPF程序链接和BPF对象
  bpf_link__destroy(link);
  bpf_object__close(obj);
  return 0;
}

// 从trace_pipe文件读取追踪数据
void read_trace_pipe(void) {
  int trace_fd;

  // 打开trace_pipe文件
  trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
  if (trace_fd < 0) return;

  // 无限循环读取并输出trace_pipe文件中的数据
  while (1) {
    static char buf[4096];
    ssize_t sz;

    // 读取trace_pipe文件的数据
    sz = read(trace_fd, buf, sizeof(buf) - 1);
    if (sz > 0) {
      buf[sz] = 0;
      // 输出读取到的数据
      puts(buf);
    }
  }
}

int main(int argc, char **argv) {
  if (load_bpf_file("01bpf_program_kern.o") != 0) {
    printf("The kernel didn't load the BPF program\n");
    return -1;
  }

  read_trace_pipe();

  return 0;
}
