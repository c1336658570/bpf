#include <benchmark/benchmark.h>
#include <array>

// 定义一个常量，表示数组的长度
constexpr int len = 6;

// constexpr函数具有inline属性，应该将它放在头文件中
constexpr auto my_pow(const int i) {
  return i * i;
}

// 使用operator[]读取元素，依次存入1-6的平方
static void bench_array_operator(benchmark::State& state) {
  // 创建一个长度为len的std::array
  std::array<int, len> arr;
  // 定义初始值i
  constexpr int i = 1;
  // 基准测试循环
  for (auto _ : state) {
    // 通过operator[]写入数组元素，依次存入1-6的平方
    arr[0] = my_pow(i);
    arr[1] = my_pow(i + 1);
    arr[2] = my_pow(i + 2);
    arr[3] = my_pow(i + 3);
    arr[4] = my_pow(i + 4);
    arr[5] = my_pow(i + 5);
  }
}
BENCHMARK(bench_array_operator);

// 使用at()读取元素，依次存入1-6的平方
static void bench_array_at(benchmark::State& state) {
  // 创建一个长度为len的std::array
  std::array<int, len> arr;
  // 定义初始值i
  constexpr int i = 1;
  // 基准测试循环
  for (auto _ : state) {
    // 通过at()写入数组元素，依次存入1-6的平方
    arr.at(0) = my_pow(i);
    arr.at(1) = my_pow(i + 1);
    arr.at(2) = my_pow(i + 2);
    arr.at(3) = my_pow(i + 3);
    arr.at(4) = my_pow(i + 4);
    arr.at(5) = my_pow(i + 5);
  }
}
BENCHMARK(bench_array_at);

// std::get<>(array)是一个constexpr函数，
// 它返回容器内元素的引用，并在编译期检查数组的索引是否正确
static void bench_array_get(benchmark::State& state) {
  // 创建一个长度为len的std::array
  std::array<int, len> arr;
  // 定义初始值i
  constexpr int i = 1;
  // 基准测试循环
  for (auto _ : state) {
    // 通过std::get<>写入数组元素，依次存入1-6的平方
    std::get<0>(arr) = my_pow(i);
    std::get<1>(arr) = my_pow(i + 1);
    std::get<2>(arr) = my_pow(i + 2);
    std::get<3>(arr) = my_pow(i + 3);
    std::get<4>(arr) = my_pow(i + 4);
    std::get<5>(arr) = my_pow(i + 5);
  }
}
BENCHMARK(bench_array_get);

// 主函数，用于运行基准测试
BENCHMARK_MAIN();
