#!/bin/env python3
# -*- coding: UTF-8 -*-
import ctypes as ct
import libpcap as pcap


class cbpf_prog:
    def __init__(self, args):
        self._len = 0
        self.ins = []
        self._tcpdump_expression_to_cbpf(args)

    # return bpf_insn list
    def _tcpdump_expression_to_cbpf(self, args: list):
        pd = pcap.open_dead(pcap.DLT_EN10MB, 262144)
        if not pd:
            print("can not open dead interface")
            return -1
        prog = pcap.bpf_program()
        cmdbuf = " ".join(args).encode("utf-8")
        mask = pcap.PCAP_NETMASK_UNKNOWN
        if pcap.compile(pd, ct.byref(prog), cmdbuf, 1, mask) < 0:
            print("can not compile tcpdump filter expression")
            pcap.close(pd)
            return -1
        if not pcap.bpf_validate(prog.bf_insns, prog.bf_len):
            print("Filter doesn't pass validation")
        self._len = prog.bf_len
        self.ins = prog.bf_insns[:self._len]

        # pcap.freecode(prog)
        pcap.close(pd)
        return 0
