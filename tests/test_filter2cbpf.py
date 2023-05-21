import subprocess
import libpcap as pcap
from pycbpf import filter2cbpf as fc

def bpf_insn_eq(insa :pcap.bpf_insn, insb :pcap.bpf_insn):
    if insa.code != insb.code:
        return False
    if insa.jt != insb.jt:
        return False
    if insa.jf != insb.jf:
        return False
    if insa.k != insb.k:
        return False
    return True

def bpf_prog_eq(insa, insb):
    if len(insa) != len(insb):
        return False
    for i, j in zip(insa, insb):
        if bpf_insn_eq(i, j) is False:
            return False
    return True

def tcpdump_args_to_bpf_insn(args):
    insn = []
    proc = subprocess.Popen(["tcpdump", "-ddd"] + args, shell=False, stdout=subprocess.PIPE)
    output, _ = proc.communicate()
    _, ins_lines = output.splitlines()[0], output.splitlines()[1:]
    for line in ins_lines:
        code, jt, jf, k = line.split()
        insn.append(pcap.bpf_insn(int(code), int(jt), int(jf), int(k)))
    return insn


def verify_cbpf_prog(args):
    largs = args.split()
    prog = fc.cbpf_prog(largs)
    ins = tcpdump_args_to_bpf_insn(largs)
    return bpf_prog_eq(prog.ins, ins)

# test indirect ld
def test_filter_2_cbpf():
    cases = ["ip", "ip6", "host 192.168.0.1", "udp port 4567", "net 192.168.0.0/24",
             "src 1.1.1.1 or 1.1.1.2", "src 1.1.1.1 and (dst 1.1.1.2 or host 1.1.1.3) and port 80",
             "ether proto 0x0806", "tcp[tcpflags] & (tcp-syn|tcp-ack) != 0",
             "icmp[0] != 8 and icmp[0] != 0", "udp[42:4]=0xAC100009"]
    for c in cases:
        assert verify_cbpf_prog(c)
