"""
The function captures packets from a network interface, applies a C Berkeley Packet Filter (cbpf) to
filter packets, and saves the filtered packets to a pcap file.
"""
import time
import ctypes
import sys
import argparse
import libpcap as pcap
from bcc import BPF


from .cbpf2c import CbpfC
from .filter2cbpf import CbpfProg

BPFTEXT = """

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


class FilterPacket(ctypes.Structure):  # pylint: disable=too-few-public-methods
    """
    The class `FilterPacket` defines a structure with a single field `packet` that is
    an array of 128 unsigned bytes.
    """
    _fields_ = [
        ("packet", ctypes.c_ubyte * 128)
    ]


def main():
    """
    ref https://github.com/iovisor/bcc/blob/master/examples/networking/dns_matching/dns_matching.py
    ret https://github.com/iovisor/bcc/blob/master/examples/tracing/undump.py
    filter packet from a raw socket
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", required=True,
                        help="interface name to run tcpdump")
    parser.add_argument("-w", "--file", dest="file",
                        default="-", help="pcap file to save packets")
    parser.add_argument("-c", "--count", dest="count", type=int, default=sys.maxsize,
                        help="number of packets to capture", )
    parser.add_argument('filter', nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if args.filter is None or len(args.filter) == 0:
        cfun = """static inline u32
cbpf_filter_func (const u8 *const data __attribute__((unused)), const u8 *const data_end __attribute__((unused))) {
	return 1;
}
"""
    else:
        prog = CbpfProg(args.filter)
        prog_c = CbpfC(prog)
        cfun = prog_c.compile_cbpf_to_c()

    text = BPFTEXT % cfun
    bctx = BPF(text=text, debug=0)

    # func_name = "__netif_receive_skb"
    func_name = "dev_queue_xmit"
    bctx.attach_kprobe(event=func_name, fn_name="filter_packets")
    pcap_dev = pcap.open_dead(pcap.DLT_EN10MB, 1000)
    # if args.file == '-':
    #     tmp = tempfile.NamedTemporaryFile()
    #     dumper = pcap.dump_open(pcap_dev, ctypes.c_char_p(tmp.name.encode("utf-8")))
    # else:
    dumper = pcap.dump_open(
        pcap_dev, ctypes.c_char_p(args.file.encode("utf-8")))

    print("Capturing packets from {func_name}... Hit Ctrl-C to end")

    counter = 0

    def filter_events_cb(_cpu, data, _size):
        nonlocal counter
        counter += 1
        event = ctypes.cast(data, ctypes.POINTER(FilterPacket)).contents
        now = time.time()
        sec = int(now)
        usec = int((now - sec) * 1e6)
        tval = pcap.timeval(sec, usec)
        hdr = pcap.pkthdr(tval, 100, 100)
        pcap.dump(ctypes.cast(dumper, ctypes.POINTER(
            ctypes.c_ubyte)), hdr, event.packet)

    bctx['filter_event'].open_perf_buffer(filter_events_cb)

    # if args.file == '-':
    #     proc = subprocess.Popen(["tcpdump", "-r", "-", "-nev"], stdin=tmp,
    #                             stdout=subprocess.PIPE, shell=False)

    while counter < args.count:
        try:
            bctx.perf_buffer_poll(timeout=1000)
            # if args.file == '-' and proc.poll() is None:
            #     output = proc.communicate(tmp.read())[0]
            #     print(output)
            #     line = proc.stdout.readline().strip(b'\n')
            #     print(line.decode())
        except KeyboardInterrupt:
            pcap.dump_close(dumper)
            pcap.close(pcap_dev)
            # if args.file == '-':
            #     proc.stdout.close()
            #     tmp.close()
            sys.exit()
    print("{counter} packets cpatured")
    pcap.dump_close(dumper)
    pcap.close(pcap_dev)


if __name__ == '__main__':
    main()
