import ctypes
import socket
import struct

from bcc import BPF, libbcc
from pycbpf import cbpf2c, filter2cbpf

BPF_TEXT = """

%s

int xdp_test_filter(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	
	u32 ret = cbpf_filter_func(data, data_end);
	if (!ret) {
		return 0;
	}
	return 1;
}
"""

# Calculate the checksum of the ICMP header and data


def checksum(data):
    length = len(data)
    left = length % 2
    csum = 0
    for i in range(0, length - left, 2):
        csum += (data[i]) + ((data[i+1]) << 8)
    if left:
        csum += (data[-1])
    csum = (csum >> 16) + (csum & 0xffff)
    csum += (csum >> 16)
    answer = ~csum & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def packet_generate(src_ip, dst_ip, proto):
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)

    eth_header = struct.pack("!6s6sH", b"\x8c\x98\xbf\xae\x54\x2c", b"\x8e\x92\xcc\xdd\xee\xff",
                             0x0800)
    # ipvl, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_sa, ip_da
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 0, 54321, 0, 64, proto, 0, ip_saddr, ip_daddr)

    if socket.IPPROTO_ICMP == proto:
        icmp_check = 0
        icmp_data = b"Hello world!"
        icmp_header = struct.pack(
            "!BBHHH", 8, 0, icmp_check, 1, 1)
        icmp_check = checksum(icmp_header + icmp_data)
        icmp_header = struct.pack(
            "!BBHHH", 8, 0, icmp_check, 1, 1)
        packet = eth_header + ip_header + icmp_header + icmp_data
    elif socket.IPPROTO_UDP == proto:
        # UDP header: src port ffff , dst port fffe , len c , check ffff
        udp_header = struct.pack("!HHHH", 21, 65534, 12, 65535)
        udp_data = b"Hello world!"
        packet = eth_header + ip_header + udp_header + udp_data
    return packet


def run_filter_test(func_fd, pkt, retval_expect):
    size = len(pkt)
    data = ctypes.create_string_buffer(pkt, size)
    data_out = ctypes.create_string_buffer(1500)
    size_out = ctypes.c_uint32()
    retval = ctypes.c_uint32()
    duration = ctypes.c_uint32()

    ret = libbcc.lib.bpf_prog_test_run(func_fd, 1,
                                       ctypes.byref(data), size,
                                       ctypes.byref(data_out),
                                       ctypes.byref(size_out),
                                       ctypes.byref(retval),
                                       ctypes.byref(duration))
    if ret != 0:
        return False
    return retval.value == retval_expect


def test_cbpf_2_c():
    prog = filter2cbpf.CbpfProg(["ip"])
    prog_c = cbpf2c.CbpfC(prog)
    cfun = prog_c.compile_cbpf_to_c()
    test_text = BPF_TEXT % cfun
    bpf_ctx = BPF(text=test_text, debug=4)
    func = bpf_ctx.load_func(func_name=b"xdp_test_filter", prog_type=BPF.XDP)

    pkt = packet_generate("192.168.0.1", "10.23.12.33", socket.IPPROTO_ICMP)
    assert run_filter_test(func.fd, pkt, 1)


def test_cbpf_2_c_host():
    prog = filter2cbpf.CbpfProg(["host", "192.168.0.1"])
    prog_c = cbpf2c.CbpfC(prog)
    cfun = prog_c.compile_cbpf_to_c()
    test_text = BPF_TEXT % cfun
    bpf_ctx = BPF(text=test_text, debug=4)
    func = bpf_ctx.load_func(func_name=b"xdp_test_filter", prog_type=BPF.XDP)

    pkt = packet_generate("192.168.0.1", "10.23.12.33", socket.IPPROTO_ICMP)
    assert run_filter_test(func.fd, pkt, 1)


def test_cbpf_2_c_host_not_match():
    prog = filter2cbpf.CbpfProg(["host", "192.168.0.2"])
    prog_c = cbpf2c.CbpfC(prog)
    cfun = prog_c.compile_cbpf_to_c()
    test_text = BPF_TEXT % cfun
    bpf_ctx = BPF(text=test_text, debug=4)
    func = bpf_ctx.load_func(func_name=b"xdp_test_filter", prog_type=BPF.XDP)

    pkt = packet_generate("192.168.0.1", "10.23.12.33", socket.IPPROTO_ICMP)
    assert run_filter_test(func.fd, pkt, 0)


def test_cbpf_2_c_icmp():
    prog = filter2cbpf.CbpfProg(["icmp[0]==8"])
    prog_c = cbpf2c.CbpfC(prog)
    cfun = prog_c.compile_cbpf_to_c()
    test_text = BPF_TEXT % cfun
    bpf_ctx = BPF(text=test_text, debug=4)
    func = bpf_ctx.load_func(func_name=b"xdp_test_filter", prog_type=BPF.XDP)

    pkt = packet_generate("192.168.0.1", "10.23.12.33", socket.IPPROTO_ICMP)
    assert run_filter_test(func.fd, pkt, 1)


# test portrange with BPF_JGE
def test_cbpf_2_c_portrange():
    prog = filter2cbpf.CbpfProg(["portrange", "21-23"])
    prog_c = cbpf2c.CbpfC(prog)
    cfun = prog_c.compile_cbpf_to_c()
    test_text = BPF_TEXT % cfun
    bpf_ctx = BPF(text=test_text, debug=4)
    func = bpf_ctx.load_func(func_name=b"xdp_test_filter", prog_type=BPF.XDP)

    pkt = packet_generate("192.168.0.1", "10.23.12.33", socket.IPPROTO_UDP)
    assert run_filter_test(func.fd, pkt, 1)


# test geneve with st/stx
def test_cbpf_2_c_geneve(): # pylint: disable=too-many-locals
    geneve_header = struct.pack(">BBHHHB", 0, 0, 0x6558, 1234 >> 8, 1234 & 0xff, 0)
    payload = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"

    geneve_packet = geneve_header + payload

    dst_mac = b"\xaa\xbb\xcc\xdd\xee\xff"  # 6 bytes
    src_mac = b"\x11\x22\x33\x44\x55\x66"  # 6 bytes

    eth_header = struct.pack(">6s6sH", dst_mac, src_mac, 0x0800)

    src_ip = b"\xc0\xa8\x01\x01"  # 4 bytes, 192.168.1.1
    dst_ip = b"\xc0\xa8\x01\x02"  # 4 bytes, 192.168.1.2
    ip_header = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + 8 + len(geneve_packet), 0,
                            0, 64, 17, 0, src_ip, dst_ip)

    udp_header = struct.pack(">HHHH", 6081, 6081, 8 + len(geneve_packet), 0)
    outer_packet = eth_header + ip_header + udp_header + geneve_packet
    prog = filter2cbpf.CbpfProg(["geneve"])
    prog_c = cbpf2c.CbpfC(prog)
    cfun = prog_c.compile_cbpf_to_c()
    bpf_ctx = BPF(text=BPF_TEXT % cfun, debug=4)
    func = bpf_ctx.load_func(func_name=b"xdp_test_filter", prog_type=BPF.XDP)
    assert run_filter_test(func.fd, outer_packet, 1)


def test_cbpf_2_c_len():
    prog = filter2cbpf.CbpfProg(["len<=100"])
    prog_c = cbpf2c.CbpfC(prog)
    cfun = prog_c.compile_cbpf_to_c()
    test_text = BPF_TEXT % cfun
    bpf_ctx = BPF(text=test_text, debug=4)
    func = bpf_ctx.load_func(func_name=b"xdp_test_filter", prog_type=BPF.XDP)

    pkt = packet_generate("192.168.0.1", "10.23.12.33", socket.IPPROTO_UDP)
    assert run_filter_test(func.fd, pkt, 1)
