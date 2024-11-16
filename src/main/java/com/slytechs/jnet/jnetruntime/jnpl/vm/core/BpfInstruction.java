package com.slytechs.jnet.jnetruntime.jnpl.vm.core;

import com.slytechs.jnet.jnetruntime.jnpl.vm.instruction.BpfOpcode;

/**
 * Represents a single BPF instruction in the VM.
 * Each instruction is encoded in a 64-bit value with the following format:
 * 
 * - opcode:    8 bits  [63-56] Operation code
 * - dst:       8 bits  [55-48] Destination register or jump true offset
 * - src:       8 bits  [47-40] Source register or jump false offset
 * - immediate: 32 bits [31-0]  Immediate value or memory offset
 */
public class BpfInstruction {
    
    private final long rawInstruction;
    
    /**
     * Creates a new BPF instruction from a raw 64-bit value.
     * 
     * @param rawInstruction The 64-bit instruction encoding
     */
    public BpfInstruction(long rawInstruction) {
        this.rawInstruction = rawInstruction;
    }
    
    /**
     * Gets the raw opcode value (8 bits).
     * 
     * @return The opcode value
     */
    public int getOpcode() {
        return (int) ((rawInstruction >>> 56) & 0xFF);
    }
    
    /**
     * Gets the destination register or jump true offset (8 bits).
     * 
     * @return The destination value
     */
    public int getDst() {
        return (int) ((rawInstruction >>> 48) & 0xFF);
    }
    
    /**
     * Gets the source register or jump false offset (8 bits).
     * 
     * @return The source value
     */
    public int getSrc() {
        return (int) ((rawInstruction >>> 40) & 0xFF);
    }
    
    /**
     * Gets the immediate value or memory offset (32 bits).
     * 
     * @return The immediate value
     */
    public int getImmediate() {
        return (int) (rawInstruction & 0xFFFFFFFF);
    }
    
    /**
     * Gets the complete raw instruction.
     * 
     * @return The raw 64-bit instruction
     */
    public long getRawInstruction() {
        return rawInstruction;
    }
    
    /**
     * Gets the opcode as an enum value.
     * 
     * @return The BpfOpcode enum value
     * @throws IllegalArgumentException if the opcode is invalid
     */
    public BpfOpcode getOpcodeEnum() {
        return BpfOpcode.fromValue(getOpcode());
    }
    
    /**
     * Creates a new instruction from components.
     * 
     * @param opcode The operation code
     * @param dst Destination register or jump true offset
     * @param src Source register or jump false offset
     * @param immediate Immediate value or memory offset
     * @return A new BpfInstruction
     */
    public static BpfInstruction create(int opcode, int dst, int src, int immediate) {
        long instruction = ((long) opcode << 56) |
                         ((long) dst << 48) |
                         ((long) src << 40) |
                         (immediate & 0xFFFFFFFFL);
        return new BpfInstruction(instruction);
    }
    
    /**
     * Creates a new instruction from an opcode enum and components.
     * 
     * @param opcode The BpfOpcode enum value
     * @param dst Destination register or jump true offset
     * @param src Source register or jump false offset
     * @param immediate Immediate value or memory offset
     * @return A new BpfInstruction
     */
    public static BpfInstruction create(BpfOpcode opcode, int dst, int src, int immediate) {
        return create(opcode.getOpcode(), dst, src, immediate);
    }
    
    @Override
    public String toString() {
        BpfOpcode opcode = getOpcodeEnum();
        return String.format("BpfInstruction[opcode=%s, dst=%d, src=%d, k=0x%x]",
                opcode.name(), getDst(), getSrc(), getImmediate());
    }
}