"""eBPF opcode fields and their names (include/uapi/linux/bpf.h).

Also the kernel-internal opcodes that only exist in a loaded program, after
the verifier's rewrites: PROBE_MEM, CALL_ARGS and TAIL_CALL.
"""

LD, LDX, ST, STX, ALU, JMP, JMP32, ALU64 = range(8)
CLASS_NAMES = ("ld", "ldx", "st", "stx", "alu", "jmp", "jmp32", "alu64")

K, X = 0x00, 0x08
TO_LE, TO_BE = K, X

W, H, B, DW = 0x00, 0x08, 0x10, 0x18
SIZE_NAMES = {W: "u32", H: "u16", B: "u8", DW: "u64"}
SIZE_NAMES_SX = {W: "s32", H: "s16", B: "s8"}

IMM, ABS, IND, MEM, MEMSX, ATOMIC = 0x00, 0x20, 0x40, 0x60, 0x80, 0xC0
PROBE_MEM = 0x20  # LDX: a load through a BTF pointer, faults caught
NOSPEC = 0xC0  # ST: speculation barrier

ADD, SUB, MUL, DIV, OR, AND, LSH, RSH, NEG, MOD, XOR, MOV, ARSH, END = range(0x00, 0xE0, 0x10)
JA, JEQ, JGT, JGE, JSET, JNE, JSGT, JSGE, CALL, EXIT, JLT, JLE, JSLT, JSLE = range(0x00, 0xE0, 0x10)
CALL_ARGS, TAIL_CALL = 0xE0, 0xF0

FETCH = 0x01
XCHG = 0xE0 | FETCH
CMPXCHG = 0xF0 | FETCH

LD_IMM64 = LD | DW | IMM

# src_reg of an ld_imm64
PSEUDO_MAP_FD, PSEUDO_MAP_VALUE, PSEUDO_BTF_ID, PSEUDO_FUNC, PSEUDO_MAP_IDX, PSEUDO_MAP_IDX_VALUE = range(1, 7)
# src_reg of a call
PSEUDO_CALL, PSEUDO_KFUNC_CALL = 1, 2

# off of ALU64 | MOV | X
ADDR_SPACE_CAST, ADDR_PERCPU = 1, -1

ALU_OPS = {ADD: "+=", SUB: "-=", MUL: "*=", DIV: "/=", OR: "|=", AND: "&=", LSH: "<<=", RSH: ">>=", MOD: "%=",
           XOR: "^=", MOV: "=", ARSH: "s>>="}
ALU_SIGNED_OPS = {DIV: "s/=", MOD: "s%="}
MOVSX = {8: "(s8)", 16: "(s16)", 32: "(s32)"}
JMP_OPS = {JA: "jmp", JEQ: "==", JGT: ">", JGE: ">=", JSET: "&", JNE: "!=", JSGT: "s>", JSGE: "s>=", CALL: "call",
           EXIT: "exit", JLT: "<", JLE: "<=", JSLT: "s<", JSLE: "s<="}
ATOMIC_OPS = {ADD: "add", AND: "and", OR: "or", XOR: "xor"}
