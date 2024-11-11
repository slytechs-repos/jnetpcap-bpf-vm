package com.slytechs.jnet.jnetruntime.bpf.vm.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.slytechs.jnet.jnetruntime.bpf.vm.instruction.BpfOpcode;

/**
 * Disassembles tcpdump-style BPF program text into executable instructions.
 */
public class BpfDisassembler {

    // Regular expression patterns for parsing
    private static final Pattern LINE_PATTERN = Pattern.compile("\\((\\d{3})\\)\\s+(\\w+)\\s+(.*)");
    private static final Pattern MEMORY_ABS_PATTERN = Pattern.compile("\\[(\\d+)\\]");
    private static final Pattern MEMORY_IND_PATTERN = Pattern.compile("\\[x \\+ (\\d+)\\]");
    private static final Pattern IMMEDIATE_PATTERN = Pattern.compile("#(0x[0-9a-fA-F]+|\\d+)");
    private static final Pattern JUMP_PATTERN = Pattern.compile(
            "#(0x[0-9a-fA-F]+|\\d+)\\s+jt\\s+(\\d+)\\s+jf\\s+(\\d+)");
    private static final Pattern MEMORY_REG_PATTERN = Pattern.compile("M\\[(\\d+)\\]");
    private static final Pattern JUMP_UNCOND_PATTERN = Pattern.compile("\\+(\\d+)");

    // Map of tcpdump mnemonics to BPF opcodes
    private static final Map<String, BpfOpcode> OPCODE_MAP = new HashMap<>();

    static {
        // Initialize opcode mapping
        OPCODE_MAP.put("ld", BpfOpcode.LD_IMM);          // May need to adjust based on operand
        OPCODE_MAP.put("ldh", BpfOpcode.LD_ABS_H);
        OPCODE_MAP.put("ldb", BpfOpcode.LD_ABS_B);
        OPCODE_MAP.put("ldx", BpfOpcode.LDX_IMM);        // May need to adjust based on operand
        OPCODE_MAP.put("ldxh", BpfOpcode.LDX_MSH);       // Special case for LDX_MSH
        OPCODE_MAP.put("st", BpfOpcode.ST);
        OPCODE_MAP.put("stx", BpfOpcode.STX);
        OPCODE_MAP.put("add", BpfOpcode.ADD_K);
        OPCODE_MAP.put("sub", BpfOpcode.SUB_K);
        OPCODE_MAP.put("mul", BpfOpcode.MUL_K);
        OPCODE_MAP.put("div", BpfOpcode.DIV_K);
        OPCODE_MAP.put("and", BpfOpcode.AND_K);
        OPCODE_MAP.put("or", BpfOpcode.OR_K);
        OPCODE_MAP.put("lsh", BpfOpcode.LSH_K);
        OPCODE_MAP.put("rsh", BpfOpcode.RSH_K);
        OPCODE_MAP.put("mod", BpfOpcode.MOD_K);
        OPCODE_MAP.put("xor", BpfOpcode.XOR_K);
        OPCODE_MAP.put("neg", BpfOpcode.NEG);
        OPCODE_MAP.put("ja", BpfOpcode.JMP_JA);
        OPCODE_MAP.put("jeq", BpfOpcode.JMP_JEQ_K);
        OPCODE_MAP.put("jgt", BpfOpcode.JMP_JGT_K);
        OPCODE_MAP.put("jge", BpfOpcode.JMP_JGE_K);
        OPCODE_MAP.put("jset", BpfOpcode.JMP_JSET_K);
        OPCODE_MAP.put("ret", BpfOpcode.RET_K);          // May need to adjust based on operand
        OPCODE_MAP.put("tax", BpfOpcode.TAX);
        OPCODE_MAP.put("txa", BpfOpcode.TXA);

        // Extended opcodes
        OPCODE_MAP.put("chk_crc", BpfOpcode.CHK_CRC);
        OPCODE_MAP.put("chk_l3_csum", BpfOpcode.CHK_L3_CSUM);
        OPCODE_MAP.put("chk_l4_csum", BpfOpcode.CHK_L4_CSUM);
        OPCODE_MAP.put("chk_trunc", BpfOpcode.CHK_TRUNC);
        OPCODE_MAP.put("chk_frame_len", BpfOpcode.CHK_FRAME_LEN);
        OPCODE_MAP.put("chk_proto_loc", BpfOpcode.CHK_PROTO_LOC);
    }

    /**
     * Disassembles tcpdump output into a BPF program.
     *
     * @param tcpdumpOutput The tcpdump-formatted program text
     * @return Compiled BPF program
     * @throws DisassemblyException if parsing fails
     */
    public static BpfProgram disassemble(String tcpdumpOutput) {
        List<BpfInstruction> instructions = new ArrayList<>();
        String[] lines = tcpdumpOutput.split("\n");

        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty())
                continue;

            BpfInstruction inst = parseLine(line);
            if (inst != null) {
                instructions.add(inst);
            }
        }

        return new BpfProgram(instructions.toArray(new BpfInstruction[0]));
    }

    /**
     * Parses a single line of tcpdump output.
     */
    private static BpfInstruction parseLine(String line) {
        Matcher m = LINE_PATTERN.matcher(line);
        if (!m.matches()) {
            throw new DisassemblyException("Invalid instruction format: " + line);
        }

        int lineNum = Integer.parseInt(m.group(1));
        String opcodeName = m.group(2);
        String operands = m.group(3).trim();

        BpfOpcode opcode = OPCODE_MAP.get(opcodeName.toLowerCase());
        if (opcode == null) {
            throw new DisassemblyException("Unknown opcode: " + opcodeName);
        }

        return parseInstruction(opcodeName.toLowerCase(), opcode, operands, lineNum);
    }

    /**
     * Parses instruction operands based on opcode type.
     */
    private static BpfInstruction parseInstruction(String opcodeName, BpfOpcode opcode, String operands, int lineNum) {
        switch (opcode.getFormat()) {
            case MEMORY_ABS:
                return parseMemoryAbsolute(opcode, operands);

            case MEMORY_IND:
                return parseMemoryIndirect(opcode, operands);

            case MEMORY_REG:
                return parseMemoryRegister(opcode, operands);

            case IMMEDIATE:
                return parseImmediate(opcodeName, opcode, operands);

            case JUMP_UNCOND:
                return parseJumpUnconditional(opcode, operands);

            case JUMP_COND:
                return parseJumpConditional(opcode, operands);

            case REG_ONLY:
                return BpfInstruction.create(opcode, 0, 0, 0);

            case EXTENDED:
                return parseExtended(opcode, operands);

            default:
                throw new DisassemblyException("Unsupported instruction format: " + opcode);
        }
    }

    /**
     * Parses memory absolute instructions (e.g., "ld [12]")
     */
    private static BpfInstruction parseMemoryAbsolute(BpfOpcode opcode, String operands) {
        Matcher m = MEMORY_ABS_PATTERN.matcher(operands);
        if (!m.matches()) {
            throw new DisassemblyException("Invalid memory absolute format: " + operands);
        }

        int offset = Integer.parseInt(m.group(1));
        return BpfInstruction.create(opcode, 0, 0, offset);
    }

    /**
     * Parses memory indirect instructions (e.g., "ld [x + 4]")
     */
    private static BpfInstruction parseMemoryIndirect(BpfOpcode opcode, String operands) {
        Matcher m = MEMORY_IND_PATTERN.matcher(operands);
        if (!m.matches()) {
            throw new DisassemblyException("Invalid memory indirect format: " + operands);
        }

        int offset = Integer.parseInt(m.group(1));
        return BpfInstruction.create(opcode, 0, 0, offset);
    }

    /**
     * Parses memory register instructions (e.g., "st M[5]")
     */
    private static BpfInstruction parseMemoryRegister(BpfOpcode opcode, String operands) {
        Matcher m = MEMORY_REG_PATTERN.matcher(operands);
        if (!m.matches()) {
            throw new DisassemblyException("Invalid memory register format: " + operands);
        }

        int reg = Integer.parseInt(m.group(1));
        return BpfInstruction.create(opcode, reg, 0, 0);
    }

    private static BpfInstruction parseImmediate(String opcodeName, BpfOpcode opcode, String operands) {
        Matcher m = IMMEDIATE_PATTERN.matcher(operands);
        if (!m.find()) {
            throw new DisassemblyException("Invalid immediate format: " + operands);
        }

        String value = m.group(1);
        long immediate;

        try {
            if (value.startsWith("0x")) {
                immediate = Long.parseLong(value.substring(2), 16) & 0xFFFFFFFFL;
            } else {
                immediate = Long.parseLong(value);
            }

            if (immediate < 0 || immediate > 0xFFFFFFFFL) {
                throw new DisassemblyException("Immediate value out of range: " + value);
            }
        } catch (NumberFormatException e) {
            throw new DisassemblyException("Invalid immediate value format: " + value);
        }

        // Handle special cases where the opcode may vary based on operands
        if (opcode == BpfOpcode.LD_IMM) {
            if (operands.equals("len")) {
                opcode = BpfOpcode.LD_LEN;
                return BpfInstruction.create(opcode, 0, 0, 0);
            } else if (operands.startsWith("M[")) {
                opcode = BpfOpcode.LD_MEM;
                return parseMemoryRegister(opcode, operands);
            }
        } else if (opcode == BpfOpcode.LDX_IMM) {
            if (operands.equals("len")) {
                opcode = BpfOpcode.LDX_LEN;
                return BpfInstruction.create(opcode, 0, 0, 0);
            } else if (operands.startsWith("M[")) {
                opcode = BpfOpcode.LDX_MEM;
                return parseMemoryRegister(opcode, operands);
            }
        } else if (opcode == BpfOpcode.RET_K) {
            if (operands.equals("a")) {
                opcode = BpfOpcode.RET_A;
                return BpfInstruction.create(opcode, 0, 0, 0);
            }
        }

        return BpfInstruction.create(opcode, 0, 0, (int) immediate);
    }

    /**
     * Parses unconditional jump instructions (e.g., "ja +2")
     */
    private static BpfInstruction parseJumpUnconditional(BpfOpcode opcode, String operands) {
        Matcher m = JUMP_UNCOND_PATTERN.matcher(operands);
        if (!m.matches()) {
            throw new DisassemblyException("Invalid unconditional jump format: " + operands);
        }

        int offset = Integer.parseInt(m.group(1));
        return BpfInstruction.create(opcode, 0, 0, offset);
    }

    private static BpfInstruction parseJumpConditional(BpfOpcode opcode, String operands) {
        Matcher m = JUMP_PATTERN.matcher(operands);
        if (!m.find()) {
            throw new DisassemblyException("Invalid conditional jump format: " + operands);
        }

        String immStr = m.group(1);
        long immediate;

        try {
            if (immStr.startsWith("0x")) {
                immediate = Long.parseLong(immStr.substring(2), 16) & 0xFFFFFFFFL;
            } else {
                immediate = Long.parseLong(immStr);
            }

            if (immediate > 0xFFFFFFFFL) {
                throw new DisassemblyException("Immediate value too large: " + immStr);
            }
        } catch (NumberFormatException e) {
            throw new DisassemblyException("Invalid immediate value format: " + immStr);
        }

        // Parse jump targets
        int jt = Integer.parseInt(m.group(2));
        int jf = Integer.parseInt(m.group(3));

        return BpfInstruction.create(opcode, jt, jf, (int) immediate);
    }

    /**
     * Parses extended instructions.
     */
    private static BpfInstruction parseExtended(BpfOpcode opcode, String operands) {
        switch (opcode) {
            case CHK_CRC:
                // Format: crc offset=<offset> len=<length>
                Pattern crcPattern = Pattern.compile("crc offset=(\\d+) len=(\\d+)");
                Matcher crcMatcher = crcPattern.matcher(operands);
                if (!crcMatcher.matches()) {
                    throw new DisassemblyException("Invalid CHK_CRC format: " + operands);
                }
                int offset = Integer.parseInt(crcMatcher.group(1));
                int length = Integer.parseInt(crcMatcher.group(2));
                return BpfInstruction.create(opcode, 0, length, offset);

            case CHK_FRAME_LEN:
                // Format: frame_len >=<value>
                Pattern frameLenPattern = Pattern.compile("frame_len >=(\\d+)");
                Matcher frameLenMatcher = frameLenPattern.matcher(operands);
                if (!frameLenMatcher.matches()) {
                    throw new DisassemblyException("Invalid CHK_FRAME_LEN format: " + operands);
                }
                int frameLen = Integer.parseInt(frameLenMatcher.group(1));
                return BpfInstruction.create(opcode, 0, 0, frameLen);

            case CHK_PROTO_LOC:
                // Format: proto_loc layer=<layer> offset=<offset>
                Pattern protoLocPattern = Pattern.compile("proto_loc layer=(\\d+) offset=(\\d+)");
                Matcher protoLocMatcher = protoLocPattern.matcher(operands);
                if (!protoLocMatcher.matches()) {
                    throw new DisassemblyException("Invalid CHK_PROTO_LOC format: " + operands);
                }
                int layer = Integer.parseInt(protoLocMatcher.group(1));
                int protoOffset = Integer.parseInt(protoLocMatcher.group(2));
                return BpfInstruction.create(opcode, layer, 0, protoOffset);

            case CHK_L3_CSUM:
            case CHK_L4_CSUM:
            case CHK_TRUNC:
                // No operands
                return BpfInstruction.create(opcode, 0, 0, 0);

            default:
                throw new DisassemblyException("Unknown extended opcode: " + opcode);
        }
    }

    /**
     * Disassembles tcpdump output in either text (-d) or hex (-dd) format.
     *
     * @param input       The tcpdump formatted program text
     * @param isHexFormat true if input is in -dd format, false for -d format
     * @return Compiled BPF program
     * @throws DisassemblyException if parsing fails
     */
    public static BpfProgram disassemble(String input, boolean isHexFormat) {
        if (isHexFormat) {
            return BpfHexDisassembler.disassembleHex(input);
        } else {
            return disassemble(input);
        }
    }

    /**
     * Attempts to auto-detect the format and disassemble accordingly.
     *
     * @param input The tcpdump formatted program text
     * @return Compiled BPF program
     * @throws DisassemblyException if parsing fails
     */
    public static BpfProgram disassembleAuto(String input) {
        // Check first non-empty, non-warning line
        String[] lines = input.split("\n");
        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("Warning:"))
                continue;

            // Check if it matches hex format
            if (line.startsWith("{") && line.contains("0x")) {
                return BpfHexDisassembler.disassembleHex(input);
            } else if (line.startsWith("(")) {
                return disassemble(input);
            }
        }

        throw new DisassemblyException("Unable to detect input format");
    }

    /**
     * Exception class for disassembly errors.
     */
    public static class DisassemblyException extends RuntimeException {
        public DisassemblyException(String message) {
            super(message);
        }
    }

    // Placeholder classes for completeness (implement these as needed)
    public static class BpfProgram {
        private final BpfInstruction[] instructions;

        public BpfProgram(BpfInstruction[] instructions) {
            this.instructions = instructions;
        }

        public BpfInstruction[] getInstructions() {
            return instructions;
        }
    }

    public static class BpfInstruction {
        private final BpfOpcode opcode;
        private final int dst;
        private final int src;
        private final int immediate;

        public static BpfInstruction create(BpfOpcode opcode, int dst, int src, int immediate) {
            return new BpfInstruction(opcode, dst, src, immediate);
        }

        public BpfInstruction(BpfOpcode opcode, int dst, int src, int immediate) {
            this.opcode = opcode;
            this.dst = dst;
            this.src = src;
            this.immediate = immediate;
        }

        public BpfOpcode getOpcodeEnum() {
            return opcode;
        }

        public int getDst() {
            return dst;
        }

        public int getSrc() {
            return src;
        }

        public int getImmediate() {
            return immediate;
        }
    }

    // Placeholder class (implement as needed)
    public static class BpfHexDisassembler {
        public static BpfProgram disassembleHex(String input) {
            // Implement hex disassembly logic here
            throw new UnsupportedOperationException("Hex disassembly not implemented");
        }
    }

    // Placeholder class (implement as needed)
    public static class BpfProgramDumper {
        public static String dump(BpfProgram program) {
            // Implement program dumping logic here
            StringBuilder sb = new StringBuilder();
            int lineNum = 0;
            for (BpfInstruction inst : program.getInstructions()) {
                sb.append(String.format("(%03d) %s\n", lineNum++, formatInstruction(inst)));
            }
            return sb.toString();
        }

        private static String formatInstruction(BpfInstruction inst) {
            // Implement instruction formatting logic here
            return inst.getOpcodeEnum().getMnemonic();
        }
    }
}
