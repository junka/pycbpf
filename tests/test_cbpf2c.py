import ctypes
import socket
import struct

from bcc import BPF, libbcc
from pycbpf import cbpf2c, filter2cbpf

bpf_text = """

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
    n = len(data)
    m = n % 2
    csum = 0
    for i in range(0, n - m , 2):
        csum += (data[i]) + ((data[i+1]) << 8)
    if m:
        csum += (data[-1])
    csum = (csum >> 16) + (csum & 0xffff)
    csum += (csum >> 16)
    answer = ~csum & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def packet_generate(src_ip, dst_ip, proto):
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)

    ip_tos = 0
    ip_tot_len = 40
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = proto
    ip_check = 0
    eth_header = struct.pack("!6s6sH", b"\x8c\x98\xbf\xae\x54\x2c", b"\x8e\x92\xcc\xdd\xee\xff",
                            0x0800)
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, ip_tos, ip_tot_len, ip_id,
                            ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    if socket.IPPROTO_ICMP == proto:
        icmp_type = 8
        icmp_code = 0
        icmp_check = 0
        icmp_id = 1
        icmp_seq = 1
        icmp_data = b"Hello world!"
        icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_check, icmp_id, icmp_seq)
        icmp_check = checksum(icmp_header + icmp_data)
        icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_check, icmp_id, icmp_seq)
        packet = eth_header + ip_header + icmp_header + icmp_data
    elif socket.IPPROTO_UDP == proto:
        # UDP header: src port ffff , dst port fffe , len c , check ffff
        udp_header = struct.pack("!HHHH", 21, 65534, 12, 65535)
        udp_data = b"Hello world!"
        packet = eth_header + ip_header + udp_header + udp_data
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

    pkt = packet_generate("192.168.0.1", "10.23.12.33", socket.IPPROTO_ICMP)
    assert run_filter_test(func.fd, pkt, 1)


def test_cbpf_2_c_host():
    prog = filter2cbpf.cbpf_prog(["host", "192.168.0.1"])
    prog_c = cbpf2c.cbpf_c(prog)
    cfun = prog_c.compile_cbpf_to_c()
    test_text = bpf_text%cfun
    bpf_ctx = BPF(text=test_text, debug=4)
    func = bpf_ctx.load_func(func_name=b"xdp_test_filter", prog_type = BPF.XDP)

    pkt = packet_generate("192.168.0.1", "10.23.12.33", socket.IPPROTO_ICMP)
    assert run_filter_test(func.fd, pkt, 1)


def test_cbpf_2_c_host_not_match():
    prog = filter2cbpf.cbpf_prog(["host", "192.168.0.2"])
    prog_c = cbpf2c.cbpf_c(prog)
    cfun = prog_c.compile_cbpf_to_c()
    test_text = bpf_text%cfun
    bpf_ctx = BPF(text=test_text, debug=4)
    func = bpf_ctx.load_func(func_name=b"xdp_test_filter", prog_type = BPF.XDP)

    pkt = packet_generate("192.168.0.1", "10.23.12.33", socket.IPPROTO_ICMP)
    assert run_filter_test(func.fd, pkt, 0)


def test_cbpf_2_c_icmp():
    prog = filter2cbpf.cbpf_prog(["icmp[0]==8"])
    prog_c = cbpf2c.cbpf_c(prog)
    cfun = prog_c.compile_cbpf_to_c()
    test_text = bpf_text%cfun
    bpf_ctx = BPF(text=test_text, debug=4)
    func = bpf_ctx.load_func(func_name=b"xdp_test_filter", prog_type = BPF.XDP)

    pkt = packet_generate("192.168.0.1", "10.23.12.33", socket.IPPROTO_ICMP)
    assert run_filter_test(func.fd, pkt, 1)


# test portrange with BPF_JGE
def test_cbpf_2_c_portrange():
    prog = filter2cbpf.cbpf_prog(["portrange", "21-23"])
    prog_c = cbpf2c.cbpf_c(prog)
    cfun = prog_c.compile_cbpf_to_c()
    test_text = bpf_text%cfun
    bpf_ctx = BPF(text=test_text, debug=4)
    func = bpf_ctx.load_func(func_name=b"xdp_test_filter", prog_type = BPF.XDP)

    pkt = packet_generate("192.168.0.1", "10.23.12.33", socket.IPPROTO_UDP)
    assert run_filter_test(func.fd, pkt, 1)


#test geneve with st/stx
def test_cbpf_2_c_geneve():
    version = 0 # 2 bits
    opt_len = 0 # 6 bits
    oam = 0 # 1 bit
    critical = 0 # 1 bit
    reserved = 0 # 6 bits
    protocol_type = 0x6558 # 16 bits
    vni = 1234 # 24 bits
    reserved2 = 0 # 8 bits
    geneve_header = struct.pack(">BBHHHB", version << 6 | opt_len,
                                oam << 7 | critical << 6 | reserved,
                                protocol_type, vni >> 8, vni & 0xff, reserved2)
    payload = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"

    geneve_packet = geneve_header + payload

    dst_mac = b"\xaa\xbb\xcc\xdd\xee\xff" # 6 bytes
    src_mac = b"\x11\x22\x33\x44\x55\x66" # 6 bytes
    eth_type = 0x0800 # 2 bytes, IP protocol

    eth_header = struct.pack(">6s6sH", dst_mac, src_mac, eth_type)

    tos = 0 # 1 byte
    total_length = 20 + 8 + len(geneve_packet)
    identification = 0 # 2 bytes
    flags = 0 # 3 bits
    fragment_offset = 0 # 13 bits
    ttl = 64 # 1 byte
    protocol = 17 # 1 byte, UDP protocol
    ip_checksum = 0 # 2 bytes, to be calculated later
    src_ip = b"\xc0\xa8\x01\x01" # 4 bytes, 192.168.1.1
    dst_ip = b"\xc0\xa8\x01\x02" # 4 bytes, 192.168.1.2
    ip_header = struct.pack(">BBHHHBBH4s4s", 0x45, tos, total_length, identification,
                            flags << 13 | fragment_offset, ttl, protocol, ip_checksum,
                            src_ip, dst_ip)

    src_port = 6081 # 2 bytes
    dst_port = 6081 # 2 bytes
    length = 8 + len(geneve_packet) # 2 bytes, UDP header + Geneve packet length
    udp_checksum = 0
    udp_header = struct.pack(">HHHH", src_port, dst_port, length, udp_checksum)
    outer_packet = eth_header + ip_header + udp_header + geneve_packet
    prog = filter2cbpf.cbpf_prog(["geneve"])
    prog_c = cbpf2c.cbpf_c(prog)
    cfun = prog_c.compile_cbpf_to_c()
    test_text = bpf_text%cfun
    bpf_ctx = BPF(text=test_text, debug=4)
    func = bpf_ctx.load_func(func_name=b"xdp_test_filter", prog_type = BPF.XDP)
    assert run_filter_test(func.fd, outer_packet, 1)


def test_cbpf_2_c_len():
    prog = filter2cbpf.cbpf_prog(["len<=100"])
    prog_c = cbpf2c.cbpf_c(prog)
    cfun = prog_c.compile_cbpf_to_c()
    test_text = bpf_text%cfun
    bpf_ctx = BPF(text=test_text, debug=4)
    func = bpf_ctx.load_func(func_name=b"xdp_test_filter", prog_type = BPF.XDP)

    pkt = packet_generate("192.168.0.1", "10.23.12.33", socket.IPPROTO_UDP)
    assert run_filter_test(func.fd, pkt, 1)
