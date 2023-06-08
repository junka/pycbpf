"""
 The CbpfProg class converts a tcpdump filter expression into a bpf_insn list using libpcap.
"""
#!/bin/env python3
# -*- coding: UTF-8 -*-
import ctypes as ct
import libpcap as pcap


class CbpfProg():  # pylint: disable=too-few-public-methods
    """
    The `CbpfProg` class converts a tcpdump filter expression into a bpf_insn list.
    """

    def __init__(self, args):
        self._len = 0
        self.ins = []
        self._tcpdump_expression_to_cbpf(args)

    # return bpf_insn list
    def _tcpdump_expression_to_cbpf(self, args: list):
        pcap_dev = pcap.open_dead(pcap.DLT_EN10MB, 262144)
        if not pcap_dev:
            print("can not open dead interface")
            return -1
        prog = pcap.bpf_program()
        cmdbuf = " ".join(args).encode("utf-8")
        mask = pcap.PCAP_NETMASK_UNKNOWN
        if pcap.compile(pcap_dev, ct.byref(prog), cmdbuf, 1, mask) < 0:
            print("can not compile tcpdump filter expression")
            pcap.close(pcap_dev)
            return -1
        if not pcap.bpf_validate(prog.bf_insns, prog.bf_len):
            print("Filter doesn't pass validation")
        self._len = prog.bf_len
        self.ins = prog.bf_insns[:self._len]

        # pcap.freecode(prog)
        pcap.close(pcap_dev)
        return 0
