// g++ -o benchmark1 benchmark1.cc -lbenchmark -lpthread
#include <benchmark/benchmark.h>
#include <iostream>

// 基准测试函数，用于测试字符串创建的性能。benchmark::State&负责测试的运行及额外参数的传递。
static void BM_StringCreation(benchmark::State& state) {
  /*
   * state.iterations(): 返回迭代次数，即当前基准测试运行的总迭代次数。
   * state.iterations() * state.threads -> 所有迭代的实际执行次数，考虑了线程数。
   * state.counters["name"]: 返回名为 "name" 的计数器的值，用于记录额外的信息。
   */
  // 循环运行基准测试，其中state会自动迭代，state会选择合适的次数来运行循环，时间的计算从循环内的语句开始
  for (auto _ : state) {
    // 在每次迭代中创建一个空字符串
    std::string empty_string;
  }
}

// 注册函数作为一个基准测试。使用BENCHMARK(<function_name>);将我们的测试用例注册进benchmark
BENCHMARK(BM_StringCreation);

// 运行基准测试的主函数。用BENCHMARK_MAIN();替代直接编写的main函数，它会处理命令行参数并运行所有注册过的测试用例生成测试结果。
BENCHMARK_MAIN();
