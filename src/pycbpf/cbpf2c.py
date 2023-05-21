import argparse
import libpcap as pcap
from .filter2cbpf import cbpf_prog

"""
BPF compile to C class
ref https://www.kernel.org/doc/Documentation/networking/filter.txt
The BPF architecture consists of the following basic elements:
  Element          Description

  A                32 bit wide accumulator
  X                32 bit wide X register
  M[]              16 x 32 bit wide misc registers aka "scratch memory
                   store", addressable from 0 to 15

A program, that is translated by bpf_asm into "opcodes" is an array that
consists of the following elements (as already mentioned):

  op:16, jt:8, jf:8, k:32

The element op is a 16 bit wide opcode that has a particular instruction
encoded. jt and jf are two 8 bit wide jump targets, one for condition
"jump if true", the other one "jump if false". Eventually, element k
contains a miscellaneous argument that can be interpreted in different
ways depending on the given instruction in op.

The instruction set consists of load, store, branch, alu, miscellaneous
and return instructions that are also represented in bpf_asm syntax. This
table lists all bpf_asm instructions available resp. what their underlying
opcodes as defined in linux/filter.h stand for:
 Instruction      Addressing mode      Description

  ld               1, 2, 3, 4, 12       Load word into A
  ldi              4                    Load word into A
  ldh              1, 2                 Load half-word into A
  ldb              1, 2                 Load byte into A
  ldx              3, 4, 5, 12          Load word into X
  ldxi             4                    Load word into X
  ldxb             5                    Load byte into X

  st               3                    Store A into M[]
  stx              3                    Store X into M[]

  jmp              6                    Jump to label
  ja               6                    Jump to label
  jeq              7, 8, 9, 10          Jump on A == <x>
  jneq             9, 10                Jump on A != <x>
  jne              9, 10                Jump on A != <x>
  jlt              9, 10                Jump on A <  <x>
  jle              9, 10                Jump on A <= <x>
  jgt              7, 8, 9, 10          Jump on A >  <x>
  jge              7, 8, 9, 10          Jump on A >= <x>
  jset             7, 8, 9, 10          Jump on A &  <x>

  add              0, 4                 A + <x>
  sub              0, 4                 A - <x>
  mul              0, 4                 A * <x>
  div              0, 4                 A / <x>
  mod              0, 4                 A % <x>
  neg                                   !A
  and              0, 4                 A & <x>
  or               0, 4                 A | <x>
  xor              0, 4                 A ^ <x>
  lsh              0, 4                 A << <x>
  rsh              0, 4                 A >> <x>

  tax                                   Copy A into X
  txa                                   Copy X into A

  ret              4, 11                Return
"""
class cbpf_c:
    def __init__(self, bpf):
        self._pc = 0
        self._jumpLabels = {}
        self._aluOps = {
            pcap.BPF_ADD : "+",
            pcap.BPF_SUB : "-",
            pcap.BPF_MUL : "*",
            pcap.BPF_DIV : "/",
            pcap.BPF_AND : "&",
            pcap.BPF_LSH : "<<",
            pcap.BPF_RSH : ">>",
            pcap.BPF_MOD : "%",
            pcap.BPF_XOR : "^",
        }
        self._bpf = bpf

    def _jump_label(self, pos):
        self._jumpLabels[pos] = "label%d" % pos
        return "label%d" % pos

    def _jump_cases(self, ins, cond, neg):
        if ins.jf == 0:
            return "if (A %s %s) {goto %s;}" % (cond, self._alu_src(ins),
                                                self._jump_label(self._pc + 1 + ins.jt))
        if ins.jt == 0:
            return "if (A %s %s) {goto %s;}" % (neg, self._alu_src(ins),
                                                self._jump_label(self._pc + 1 + ins.jf))
        else:
            return "if (A %s %s) {goto %s;} else { goto %s;}" % (cond, self._alu_src(ins),
                                                    self._jump_label(self._pc + 1 + ins.jt),
                                                    self._jump_label(self._pc + 1 + ins.jf))

    def _ld_dst(self, ins):
        if pcap.BPF_CLASS(ins.code) == pcap.BPF_LD:
            return "A"
        elif pcap.BPF_CLASS(ins.code) == pcap.BPF_LDX:
            return "X"

    def _alu_src(self, ins):
        if pcap.BPF_SRC(ins.code) == pcap.BPF_K:
            return "0x%x" % ins.k
        elif pcap.BPF_SRC(ins.code) == pcap.BPF_X:
            return "X"

    def _load_data_size(self, ins, data):
        check = ""
        if pcap.BPF_SIZE(ins.code) == pcap.BPF_B:
            width = 1
        elif pcap.BPF_SIZE(ins.code) == pcap.BPF_H:
            width = 2
        elif pcap.BPF_SIZE(ins.code) == pcap.BPF_W:
            width = 4
        if data == "data":
            check = "if (data + %d + %d > data_end) { return 0; }\n\t" % (ins.k, width)
        elif data == "indirect":
            # ref https://www.kernel.org/doc/Documentation/networking/filter.txt
            check = "if (data + X > data_end) {return 0;}\n\t"
            check += "indirect = data + X;\n\t"
            check += "if (indirect + %d + %d > data_end) {return 0;}\n\t" % (ins.k, width)

        if pcap.BPF_SIZE(ins.code) == pcap.BPF_B:
            return "%s%s = *(%s + %d);" % (check, self._ld_dst(ins), data, ins.k)
        elif pcap.BPF_SIZE(ins.code) == pcap.BPF_H:
            return "%s%s = bpf_ntohs(*((u16 *)(%s + %d)));" % (check, self._ld_dst(ins),
                                                               data, ins.k)
        elif pcap.BPF_SIZE(ins.code) == pcap.BPF_W:
            return "%s%s = bpf_ntohl(*((u32 *) (%s + %d)));" % (check, self._ld_dst(ins),
                                                                data, ins.k)


    # ref https://github.com/iovisor/bpf-docs/blob/master/eBPF.md
    """
    LD/LDX/ST/STX opcode structure:

    msb      lsb
    +---+--+---+
    |mde|sz|cls|
    +---+--+---+
    BPF_SIZE
    BPF_MODE
    BPF_CLASS
    The sz field specifies the size of the memory location. The mde field is the
    memory access mode. uBPF only supports the generic "MEM" access mode.

    ALU/ALU64/JMP opcode structure:

    msb      lsb
    +----+-+---+
    |op  |s|cls|
    +----+-+---+
    BPF_OP
    BPF_SRC
    BPF_CLASS
    If the s bit is zero, then the source operand is imm. If s is one, then the source
    operand is src. The op field specifies which ALU or branch operation is to be performed.
    """
    def compile_cbpf_to_c(self) -> str:
        ctext = """\nstatic inline u32
cbpf_filter_func (const u8 *const data, const u8 *const data_end) {
	__attribute__((unused)) u32 A, X, M[16];
	__attribute__((unused)) const u8 *indirect;
"""
        for ins in self._bpf.ins:
            ctext += "\n"
            if self._jumpLabels.get(self._pc) is not None:
                ctext += self._jumpLabels.get(self._pc) + ":\n"
            ctext += "\t%s" % self._convert_insn(ins)
            self._pc += 1
        ctext += "\n}"
        return ctext

    #ref https://github.com/the-tcpdump-group/libpcap/blob/master/bpf_filter.c
    # ref bpf(7) https://www3.physnet.uni-hamburg.de/physnet/Tru64-Unix/HTML/MAN/MAN7/0012____.HTM
    def _convert_insn(self, ins) -> str:
        # print("{0x%x, %d, %d, 0x%x}" % (ins.code, ins.jt, ins.jf, ins.k))
        if pcap.BPF_CLASS(ins.code) == pcap.BPF_LD or pcap.BPF_CLASS(ins.code) == pcap.BPF_LDX:
            if pcap.BPF_MODE(ins.code) == pcap.BPF_IMM:
                return "%s = %u;" % (self._ld_dst(ins), ins.k)
            if pcap.BPF_MODE(ins.code) == pcap.BPF_IND:
                return self._load_data_size(ins, "indirect")
            elif pcap.BPF_MODE(ins.code) == pcap.BPF_ABS:
                return self._load_data_size(ins, "data")
            elif pcap.BPF_MODE(ins.code) == pcap.BPF_MEM:
                return "%s = M[%d];" % (self._ld_dst(ins), ins.k)
            elif pcap.BPF_MODE(ins.code) == pcap.BPF_LEN:
                return "%s = data_end - data;" % (self._ld_dst(ins))
            elif pcap.BPF_MODE(ins.code) == pcap.BPF_MSH:
                return self._load_data_size(ins, "data") + "X = (X & 0xF)<< 2;"

        elif pcap.BPF_CLASS(ins.code) == pcap.BPF_ST:
            return "M[%d] = A;" % ins.k
        elif pcap.BPF_CLASS(ins.code) == pcap.BPF_STX:
            return "M[%d] = X;" % ins.k

        elif pcap.BPF_CLASS(ins.code) == pcap.BPF_ALU:
            if pcap.BPF_OP(ins.code) == pcap.BPF_NEG:
                return "A = -A;"
            elif pcap.BPF_OP(ins.code) > pcap.BPF_XOR:
                return "NOT Support"
            return "A %s= %s;" % (self._aluOps.get(pcap.BPF_OP(ins.code)), self._alu_src(ins))

        elif pcap.BPF_CLASS(ins.code) == pcap.BPF_JMP:
            """
            - Conditional jt/jf targets replaced with jt/fall-through:

            While the original design has constructs such as "if (cond) jump_true;
            else jump_false;", they are being replaced into alternative constructs like
            "if (cond) jump_true; /* else fall-through */".
            """
            if pcap.BPF_OP(ins.code) == pcap.BPF_JA:
                return "goto %s" % self._jump_label(ins.k)
            if pcap.BPF_OP(ins.code) == pcap.BPF_JEQ:
                return self._jump_cases(ins, "==", "!=")
            if pcap.BPF_OP(ins.code) == pcap.BPF_JGT:
                return self._jump_cases(ins, ">", "<=")
            if pcap.BPF_OP(ins.code) == pcap.BPF_JGE:
                return self._jump_cases(ins, ">=", "<")
            if pcap.BPF_OP(ins.code) == pcap.BPF_JSET:
                return self._jump_cases(ins, "&", "|")

        elif pcap.BPF_CLASS(ins.code) == pcap.BPF_RET:
            if pcap.BPF_RVAL(ins.code) == pcap.BPF_A:
                return "return A;"
            else:
                return "return %d;" % ins.k

        elif pcap.BPF_CLASS(ins.code) == pcap.BPF_MISC:
            if pcap.BPF_MISCOP(ins.code) == pcap.BPF_TAX:
                return "X = A;"
            elif pcap.BPF_MISCOP(ins.code) == pcap.BPF_TXA:
                return "A = X;"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="interface name to run tcpdump")
    parser.add_argument('filter', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.filter and len(args.filter) > 0:
        prog = cbpf_prog(args.filter)
        prog_c = cbpf_c(prog)
        cfun = prog_c.compile_cbpf_to_c()
        print(cfun)

if __name__ == '__main__':
    main()
