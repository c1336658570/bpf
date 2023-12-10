# 运行：sudo python test_xdp.py
from bcc import BPF, libbcc
from scapy.all import Ether, IP, raw, TCP, UDP

import ctypes
import unittest

# 使用Python单元测试框架测试XDP
# BPF_PROG_TEST_RUN可以用来测试XDP程序


# 测试用例类
class XDPExampleTestCase(unittest.TestCase):
    SKB_OUT_SIZE = 1514  # mtu 1500 + 14 ethernet size
    bpf_function = None

    # 进行断言并调用bpf_prog_test_run。
    # 三个参数
    # given_packet    这是我们用来测试XDP程序的数据包，是接口接收的原始数据包。
    # expected_packet 这是我们期望在XDP程序处理色之后收到的数据包。当XDP程序返回XDP_DROP或XDP_ABORT时，
    # 我们期待它是None。在所有其他情况下，数据包与given_packet相同，或者可能被修改。
    # expected_return 这是处理我们的given_packet之后，XDP程序的预期返回。
    def _xdp_test_run(self, given_packet, expected_packet, expected_return):
        size = len(given_packet)

        # 使用ctypes库将参数转换为C类型
        given_packet = ctypes.create_string_buffer(raw(given_packet), size)
        packet_output = ctypes.create_string_buffer(self.SKB_OUT_SIZE)

        packet_output_size = ctypes.c_uint32()
        test_retval = ctypes.c_uint32()
        duration = ctypes.c_uint32()
        repeat = 1
        # 调用BPF_PROG_TEST_RUN的libbcc对应项libbcc.lib.bpf_prog_test_run，
        # 使用数据包和无数据用作测试参数。然后，将根据测试调用的结果以及给定的值，进行所有的断言。
        ret = libbcc.lib.bpf_prog_test_run(self.bpf_function.fd,
                                           repeat,
                                           ctypes.byref(given_packet),
                                           size,
                                           ctypes.byref(packet_output),
                                           ctypes.byref(packet_output_size),
                                           ctypes.byref(test_retval),
                                           ctypes.byref(duration))
        self.assertEqual(ret, 0)
        self.assertEqual(test_retval.value, expected_return)

        if expected_packet:
            self.assertEqual(
                packet_output[:packet_output_size.value], raw(expected_packet))

    # setUp方法将通过打开和编译program.c源文件(即XDP代码所在的文件)，完成对BPF程序myprogram的实际加载
    def setUp(self):
        bpf_prog = BPF(src_file=b"program.c")
        self.bpf_function = bpf_prog.load_func(b"myprogram", BPF.XDP)

    # 测试一下是否将丢弃所有TCP数据包。
    def test_drop_tcp(self):
        # 在given_packet中创建了一个IPv4上的TCP数据包。
        given_packet = Ether() / IP() / TCP()
        # 使用断言方法_xdp_test_run验证给定数据包，我们将获得XDP_DROP并且不附带返回数据包:
        self._xdp_test_run(given_packet, None, BPF.XDP_DROP)

    def test_pass_udp(self):
        # 构造了两个基本相同的UDP数据包，一个用于given_packet，一个用于expected_packet。
        given_packet = Ether() / IP() / UDP()
        expected_packet = Ether() / IP() / UDP()
        # 测试了在XDP_PASS允许的情况下，UDP数据包没有被修改
        self._xdp_test_run(given_packet, expected_packet, BPF.XDP_PASS)

    # 为了使情况更加复杂，我们决定允许进入端口9090的TCP数据包。为了实现这个目的，数据包将被重写，
    # 更改其目标MAC地址以达到重定向到特定的网络接口08:00:27:dd:38:2a。
    def test_transform_dst(self):
        # given_packet具有9090作为目的端口，我们需要expected_packet带有新目标地址和端口9090
        given_packet = Ether() / IP() / TCP(dport=9090)
        expected_packet = Ether(dst='08:00:27:dd:38:2a') / \
            IP() / TCP(dport=9090)
        self._xdp_test_run(given_packet, expected_packet, BPF.XDP_TX)


# 为测试程序编写入口点，它将仅调用unittest.main()，然后加载井执行测试
if __name__ == '__main__':
    unittest.main()
