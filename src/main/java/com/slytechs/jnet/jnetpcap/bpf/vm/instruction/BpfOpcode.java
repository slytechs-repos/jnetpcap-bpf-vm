package com.slytechs.jnet.jnetpcap.bpf.vm.instruction;

/**
 * Enumeration of BPF opcodes with associated metadata, including opcode values,
 * mnemonics, categories, and formats. This enum represents both standard and
 * extended BPF instructions.
 */
public enum BpfOpcode {

    // Load instructions (LD)
    LD_IMM(0x00, "ld   #k", Category.LOAD, Format.IMMEDIATE),
    LD_ABS_W(0x20, "ld   [k]", Category.LOAD, Format.MEMORY_ABS),
    LD_ABS_H(0x28, "ldh  [k]", Category.LOAD, Format.MEMORY_ABS),
    LD_ABS_B(0x30, "ldb  [k]", Category.LOAD, Format.MEMORY_ABS),
    LD_IND_W(0x40, "ld   [x + k]", Category.LOAD, Format.MEMORY_IND),
    LD_IND_H(0x48, "ldh  [x + k]", Category.LOAD, Format.MEMORY_IND),
    LD_IND_B(0x50, "ldb  [x + k]", Category.LOAD, Format.MEMORY_IND),
    LD_LEN(0x80, "ld   len", Category.LOAD, Format.REG_ONLY),
    LD_MEM(0x60, "ld   M[k]", Category.LOAD, Format.MEMORY_REG),
    LD_MSH(0xA0, "ld   #([k]&0xf)<<2", Category.LOAD, Format.MEMORY_ABS),

    // Load instructions (LDX)
    LDX_IMM(0x01, "ldx  #k", Category.LOAD, Format.IMMEDIATE),
    LDX_MEM(0x61, "ldx  M[k]", Category.LOAD, Format.MEMORY_REG),
    LDX_LEN(0x81, "ldx  len", Category.LOAD, Format.REG_ONLY),
    LDX_MSH(0xA1, "ldx  #([k]&0xf)<<2", Category.LOAD, Format.MEMORY_ABS),

    // Store instructions (ST/STX)
    ST(0x02, "st   M[k]", Category.STORE, Format.MEMORY_REG),
    STX(0x03, "stx  M[k]", Category.STORE, Format.MEMORY_REG),

    // ALU instructions (immediate)
    ADD_K(0x04, "add  #k", Category.ALU, Format.IMMEDIATE),
    SUB_K(0x14, "sub  #k", Category.ALU, Format.IMMEDIATE),
    MUL_K(0x24, "mul  #k", Category.ALU, Format.IMMEDIATE),
    DIV_K(0x34, "div  #k", Category.ALU, Format.IMMEDIATE),
    OR_K(0x44, "or   #k", Category.ALU, Format.IMMEDIATE),
    AND_K(0x54, "and  #k", Category.ALU, Format.IMMEDIATE),
    LSH_K(0x64, "lsh  #k", Category.ALU, Format.IMMEDIATE),
    RSH_K(0x74, "rsh  #k", Category.ALU, Format.IMMEDIATE),
    MOD_K(0x94, "mod  #k", Category.ALU, Format.IMMEDIATE),
    XOR_K(0xA4, "xor  #k", Category.ALU, Format.IMMEDIATE),
    NEG(0x84, "neg", Category.ALU, Format.REG_ONLY),

    // ALU instructions with X register
    ADD_X(0x0C, "add  x", Category.ALU, Format.REG_ONLY),
    SUB_X(0x1C, "sub  x", Category.ALU, Format.REG_ONLY),
    MUL_X(0x2C, "mul  x", Category.ALU, Format.REG_ONLY),
    DIV_X(0x3C, "div  x", Category.ALU, Format.REG_ONLY),
    OR_X(0x4C, "or   x", Category.ALU, Format.REG_ONLY),
    AND_X(0x5C, "and  x", Category.ALU, Format.REG_ONLY),
    LSH_X(0x6C, "lsh  x", Category.ALU, Format.REG_ONLY),
    RSH_X(0x7C, "rsh  x", Category.ALU, Format.REG_ONLY),
    MOD_X(0x9C, "mod  x", Category.ALU, Format.REG_ONLY),
    XOR_X(0xAC, "xor  x", Category.ALU, Format.REG_ONLY),

    // Jump instructions
    JMP_JA(0x05, "jmp  +k", Category.JUMP, Format.JUMP_UNCOND),
    JMP_JEQ_K(0x15, "jeq  #k,jt,jf", Category.JUMP, Format.JUMP_COND),
    JMP_JGT_K(0x25, "jgt  #k,jt,jf", Category.JUMP, Format.JUMP_COND),
    JMP_JGE_K(0x35, "jge  #k,jt,jf", Category.JUMP, Format.JUMP_COND),
    JMP_JSET_K(0x45, "jset #k,jt,jf", Category.JUMP, Format.JUMP_COND),
    JMP_JEQ_X(0x1D, "jeq  x,jt,jf", Category.JUMP, Format.JUMP_COND),
    JMP_JGT_X(0x2D, "jgt  x,jt,jf", Category.JUMP, Format.JUMP_COND),
    JMP_JGE_X(0x3D, "jge  x,jt,jf", Category.JUMP, Format.JUMP_COND),
    JMP_JSET_X(0x4D, "jset x,jt,jf", Category.JUMP, Format.JUMP_COND),

    // Return instructions
    RET_K(0x06, "ret  #k", Category.RET, Format.IMMEDIATE),
    RET_A(0x16, "ret  a", Category.RET, Format.REG_ONLY),

    // Miscellaneous instructions
    TAX(0x07, "tax", Category.MISC, Format.REG_ONLY),
    TXA(0x87, "txa", Category.MISC, Format.REG_ONLY),

    // Extended instructions
    CHK_CRC(0xE0, "chk_crc", Category.EXTENSION, Format.EXTENDED),
    CHK_L3_CSUM(0xE1, "chk_l3_csum", Category.EXTENSION, Format.EXTENDED),
    CHK_L4_CSUM(0xE2, "chk_l4_csum", Category.EXTENSION, Format.EXTENDED),
    CHK_TRUNC(0xE3, "chk_trunc", Category.EXTENSION, Format.EXTENDED),
    CHK_FRAME_LEN(0xE4, "chk_frame_len", Category.EXTENSION, Format.EXTENDED),
    CHK_PROTO_LOC(0xE5, "chk_proto_loc", Category.EXTENSION, Format.EXTENDED),

    // **New Extended Load Instruction**
    LDX_MEM_IND(0xB1, "ldx  M[k]", Category.LOAD, Format.MEMORY_REG);

    private final int opcode;
    private final String mnemonic;
    private final Category category;
    private final Format format;

    BpfOpcode(int opcode, String mnemonic, Category category, Format format) {
        this.opcode = opcode;
        this.mnemonic = mnemonic;
        this.category = category;
        this.format = format;
    }

    /**
     * Instruction categories for organizational and processing purposes.
     */
    public enum Category {
        LOAD,      // Load operations
        STORE,     // Store operations
        ALU,       // Arithmetic and logical operations
        JUMP,      // Branch operations
        RET,       // Return operations
        MISC,      // Miscellaneous operations
        EXTENSION  // Extended operations
    }

    /**
     * Instruction format types defining how the instruction bits should be
     * interpreted.
     */
    public enum Format {
        MEMORY_ABS,   // Absolute memory reference
        MEMORY_IND,   // Indirect memory reference
        MEMORY_REG,   // Memory reference using register
        IMMEDIATE,    // Immediate value
        REG_ONLY,     // Register-only operation
        JUMP_UNCOND,  // Unconditional jump
        JUMP_COND,    // Conditional jump
        EXTENDED      // Extended instruction format
    }

    /**
     * Get the raw opcode value.
     */
    public int getOpcode() {
        return opcode;
    }

    /**
     * Get the instruction mnemonic.
     */
    public String getMnemonic() {
        return mnemonic;
    }

    /**
     * Get the instruction category.
     */
    public Category getCategory() {
        return category;
    }

    /**
     * Get the instruction format.
     */
    public Format getFormat() {
        return format;
    }

    /**
     * Check if instruction is a load operation.
     */
    public boolean isLoad() {
        return category == Category.LOAD;
    }

    /**
     * Check if instruction is a store operation.
     */
    public boolean isStore() {
        return category == Category.STORE;
    }

    /**
     * Check if instruction is an ALU operation.
     */
    public boolean isAlu() {
        return category == Category.ALU;
    }

    /**
     * Check if instruction is a jump operation.
     */
    public boolean isJump() {
        return category == Category.JUMP;
    }

    /**
     * Check if instruction is a return operation.
     */
    public boolean isReturn() {
        return category == Category.RET;
    }

    /**
     * Check if instruction is a miscellaneous operation.
     */
    public boolean isMisc() {
        return category == Category.MISC;
    }

    /**
     * Check if instruction is an extended operation.
     */
    public boolean isExtension() {
        return category == Category.EXTENSION;
    }

    /**
     * Find opcode by raw value.
     */
    public static BpfOpcode fromValue(int value) {
        for (BpfOpcode op : values()) {
            if (op.opcode == value) {
                return op;
            }
        }
        throw new IllegalArgumentException("Invalid opcode: 0x" + Integer.toHexString(value));
    }
}
