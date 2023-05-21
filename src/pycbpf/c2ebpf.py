
import time
import ctypes
import sys
import argparse
import libpcap as pcap
from bcc import BPF


from .cbpf2c import cbpf_c
from .filter2cbpf import cbpf_prog

bpftext = """

#include <linux/skbuff.h>

#define MAX_PACKET_LEN (128)


struct filter_packet {
	u8 packet[MAX_PACKET_LEN];
};

BPF_PERF_OUTPUT(filter_event);

%s

int filter_packets (struct pt_regs *ctx) {
	struct filter_packet e = { };
	struct sk_buff *skb;
	u32 datalen = 0;
	u32 ret = 0;
	u8 *data;

	skb = (struct sk_buff*)PT_REGS_PARM1(ctx);
	data = skb->data;
	datalen = skb->len;

	/* use bpf_probe_read_user for uprobe OR bpf_probe_read_kernel for kprobe */
	if (datalen > MAX_PACKET_LEN) {
		datalen = MAX_PACKET_LEN;
	}
	bpf_probe_read_kernel(&e.packet, datalen, data);

	/* cbpf filter packet that match */
	ret = cbpf_filter_func(data, data + datalen);
	if (!ret) {
		return 0;
	}

	filter_event.perf_submit(ctx, &e, sizeof(e));
	return 0;
}


"""

class FilterPacket(ctypes.Structure):
    _fields_ = [
        ("packet", ctypes.c_ubyte * 128)
    ]


"""
ref https://github.com/iovisor/bcc/blob/master/examples/networking/dns_matching/dns_matching.py
ret https://github.com/iovisor/bcc/blob/master/examples/tracing/undump.py
filter packet from a raw socket
"""
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="interface name to run tcpdump", required=True)
    parser.add_argument("-w", "--file", help="pcap file to save packets")
    parser.add_argument('filter', nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if args.filter is None or len(args.filter) == 0:
        cfun = """static inline u32
cbpf_filter_func (const u8 *const data __attribute__((unused)), const u8 *const data_end __attribute__((unused))) {
	return 1;
}
"""
    else:
        prog = cbpf_prog(args.filter)
        prog_c = cbpf_c(prog)
        cfun = prog_c.compile_cbpf_to_c()

    if args.file is None:
        args.file = '-'
    text = bpftext%cfun
    bctx = BPF(text = text, debug = 0)

    # func_name = "__netif_receive_skb"
    func_name = "dev_queue_xmit"
    bctx.attach_kprobe(event=func_name, fn_name="filter_packets")
    pd = pcap.open_dead(pcap.DLT_EN10MB, 1000)
    dumper = pcap.dump_open(pd, ctypes.c_char_p(args.file.encode("utf-8")))
    if args.file != '-':
        print("Capturing packets from %s... Hit Ctrl-C to end" % func_name)

    def filter_events_cb(_cpu, data, _size):
        event = ctypes.cast(data, ctypes.POINTER(FilterPacket)).contents
        now = time.time()
        sec = int(now)
        usec = int((now - sec) * 1e6)
        tval = pcap.timeval(sec, usec)
        hdr = pcap.pkthdr(tval, 100, 100)
        pcap.dump(ctypes.cast(dumper, ctypes.POINTER(ctypes.c_ubyte)), hdr, event.packet)

    bctx['filter_event'].open_perf_buffer(filter_events_cb)

    while True:
        try:
            bctx.perf_buffer_poll()
        except:
            pcap.dump_close(dumper)
            pcap.close(pd)
            sys.exit()


if __name__ == '__main__' :
    main()
