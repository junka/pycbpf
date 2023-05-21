import libpcap as pcap
import ctypes
import socket
import struct

from bcc import BPF, libbcc
from pycbpf import cbpf2c, filter2cbpf

bpf_text = """

%s

#define MAX_PACKET_OFF 0xffff

int xdp_test_filter(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
    if (data >= data_end) {
		return 0;
	}
	
	u32 ret = cbpf_filter_func(data, data_end);
	if (!ret) {
		return 0;
	}
	return 1;
}
"""

# Calculate the checksum of the ICMP header and data
def checksum(data):
    n = len(data)
    m = n % 2
    sum = 0
    for i in range(0, n - m , 2):
        sum += (data[i]) + ((data[i+1]) << 8)
    if m:
        sum += (data[-1])
    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)
    answer = ~sum & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def packet_generate(src_ip, dst_ip):
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)

    ip_tos = 0
    ip_tot_len = 40
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_ICMP
    ip_check = 0

    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    icmp_type = 8
    icmp_code = 0
    icmp_check = 0
    icmp_id = 1
    icmp_seq = 1
    icmp_data = b"Hello world!"
    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_check, icmp_id, icmp_seq)
    icmp_check = checksum(icmp_header + icmp_data)
    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_check, icmp_id, icmp_seq)
    eth_header = struct.pack("!6s6sH", b"\x8c\x98\xbf\xae\x54\x2c", b"\x8e\x92\xcc\xdd\xee\xff", 0x0800)
    packet = eth_header + ip_header + icmp_header + icmp_data
    return packet

def run_filter_test(fd, pkt, retval_expect):
    size = len(pkt)
    data = ctypes.create_string_buffer(pkt, size)
    data_out = ctypes.create_string_buffer(1500)
    size_out = ctypes.c_uint32()
    retval = ctypes.c_uint32()
    duration = ctypes.c_uint32()

    ret = libbcc.lib.bpf_prog_test_run(fd, 1,
                                       ctypes.byref(data), size,
                                       ctypes.byref(data_out),
                                       ctypes.byref(size_out),
                                       ctypes.byref(retval),
                                       ctypes.byref(duration))
    if ret != 0:
        return False
    return (retval.value == retval_expect)


def test_cbpf_2_c():
    prog = filter2cbpf.cbpf_prog(["ip"])
    prog_c = cbpf2c.cbpf_c(prog)
    cfun = prog_c.compile_cbpf_to_c()
    test_text = bpf_text%cfun
    bpf_ctx = BPF(text=test_text, debug=4)
    func = bpf_ctx.load_func(func_name=b"xdp_test_filter", prog_type = BPF.XDP)

    pkt = packet_generate("192.168.0.1", "10.23.12.33")
    assert run_filter_test(func.fd, pkt, 1)


def test_cbpf_2_c_host():
    prog = filter2cbpf.cbpf_prog(["host", "192.168.0.1"])
    prog_c = cbpf2c.cbpf_c(prog)
    cfun = prog_c.compile_cbpf_to_c()
    test_text = bpf_text%cfun
    bpf_ctx = BPF(text=test_text, debug=4)
    func = bpf_ctx.load_func(func_name=b"xdp_test_filter", prog_type = BPF.XDP)

    pkt = packet_generate("192.168.0.1", "10.23.12.33")
    assert run_filter_test(func.fd, pkt, 1)


def test_cbpf_2_c_host_not_match():
    prog = filter2cbpf.cbpf_prog(["host", "192.168.0.2"])
    prog_c = cbpf2c.cbpf_c(prog)
    cfun = prog_c.compile_cbpf_to_c()
    test_text = bpf_text%cfun
    bpf_ctx = BPF(text=test_text, debug=4)
    func = bpf_ctx.load_func(func_name=b"xdp_test_filter", prog_type = BPF.XDP)

    pkt = packet_generate("192.168.0.1", "10.23.12.33")
    assert run_filter_test(func.fd, pkt, 0)


def test_cbpf_2_c_icmp():
    prog = filter2cbpf.cbpf_prog(["icmp[0]==8"])
    prog_c = cbpf2c.cbpf_c(prog)
    cfun = prog_c.compile_cbpf_to_c()
    test_text = bpf_text%cfun
    bpf_ctx = BPF(text=test_text, debug=4)
    func = bpf_ctx.load_func(func_name=b"xdp_test_filter", prog_type = BPF.XDP)

    pkt = packet_generate("192.168.0.1", "10.23.12.33")
    assert run_filter_test(func.fd, pkt, 1)