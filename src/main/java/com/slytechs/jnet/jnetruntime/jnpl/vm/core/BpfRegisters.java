package com.slytechs.jnet.jnetruntime.jnpl.vm.core;

import java.util.Arrays;

/**
 * Manages register state for the BPF virtual machine.
 * Provides access to standard BPF registers (A, X) and extended registers
 * for additional functionality.
 */
public class BpfRegisters {
    
    /** Number of general-purpose registers */
    private static final int NUM_GP_REGISTERS = 16;
    
    /** Register index for accumulator (A) */
    public static final int REG_A = 0;
    
    /** Register index for index register (X) */
    public static final int REG_X = 1;
    
    /** Register index for temporary register (M0) */
    public static final int REG_M0 = 2;
    
    /** Extension register base index */
    private static final int REG_EXT_BASE = 4;
    
    /** Error status register */
    public static final int REG_ERROR_STATUS = REG_EXT_BASE + 0;
    
    /** Frame length register */
    public static final int REG_FRAME_LEN = REG_EXT_BASE + 1;
    
    /** Protocol offset register */
    public static final int REG_PROTO_OFFSET = REG_EXT_BASE + 2;
    
    /** Layer 3 offset register */
    public static final int REG_L3_OFFSET = REG_EXT_BASE + 3;
    
    /** Layer 4 offset register */
    public static final int REG_L4_OFFSET = REG_EXT_BASE + 4;
    
    /** Payload offset register */
    public static final int REG_PAYLOAD_OFFSET = REG_EXT_BASE + 5;
    
    /** Array of register values */
    private final long[] registers;
    
    /** Tracks which registers have been written to */
    private final boolean[] modified;
    
    /** Special error bits for error status register */
    public static final long ERROR_CRC = 1L << 0;
    public static final long ERROR_L3_CHECKSUM = 1L << 1;
    public static final long ERROR_L4_CHECKSUM = 1L << 2;
    public static final long ERROR_TRUNCATED = 1L << 3;
    public static final long ERROR_MALFORMED = 1L << 4;
    
    /**
     * Creates a new register file with all registers initialized to zero.
     */
    public BpfRegisters() {
        this.registers = new long[NUM_GP_REGISTERS];
        this.modified = new boolean[NUM_GP_REGISTERS];
    }
    
    /**
     * Creates a new register file with specified initial values.
     * 
     * @param initialValues Array of initial register values
     * @throws IllegalArgumentException if initialValues length exceeds register count
     */
    public BpfRegisters(long[] initialValues) {
        if (initialValues.length > NUM_GP_REGISTERS) {
            throw new IllegalArgumentException("Too many initial values");
        }
        
        this.registers = new long[NUM_GP_REGISTERS];
        this.modified = new boolean[NUM_GP_REGISTERS];
        
        System.arraycopy(initialValues, 0, registers, 0, initialValues.length);
        Arrays.fill(modified, 0, initialValues.length, true);
    }
    
    /**
     * Gets value from specified register.
     * 
     * @param reg Register index
     * @return Register value
     * @throws IllegalArgumentException if register index is invalid
     */
    public long get(int reg) {
        validateRegister(reg);
        return registers[reg];
    }
    
    /**
     * Sets value in specified register.
     * 
     * @param reg Register index
     * @param value Value to set
     * @throws IllegalArgumentException if register index is invalid
     */
    public void set(int reg, long value) {
        validateRegister(reg);
        registers[reg] = value;
        modified[reg] = true;
    }
    
    /**
     * Gets value from accumulator (A).
     * 
     * @return Accumulator value
     */
    public long getA() {
        return registers[REG_A];
    }
    
    /**
     * Sets value in accumulator (A).
     * 
     * @param value Value to set
     */
    public void setA(long value) {
        registers[REG_A] = value;
        modified[REG_A] = true;
    }
    
    /**
     * Gets value from index register (X).
     * 
     * @return Index register value
     */
    public long getX() {
        return registers[REG_X];
    }
    
    /**
     * Sets value in index register (X).
     * 
     * @param value Value to set
     */
    public void setX(long value) {
        registers[REG_X] = value;
        modified[REG_X] = true;
    }
    
    /**
     * Gets error status register value.
     * 
     * @return Error status
     */
    public long getErrorStatus() {
        return registers[REG_ERROR_STATUS];
    }
    
    /**
     * Sets a specific error bit in the error status register.
     * 
     * @param errorBit Error bit to set
     */
    public void setError(long errorBit) {
        registers[REG_ERROR_STATUS] |= errorBit;
        modified[REG_ERROR_STATUS] = true;
    }
    
    /**
     * Clears a specific error bit in the error status register.
     * 
     * @param errorBit Error bit to clear
     */
    public void clearError(long errorBit) {
        registers[REG_ERROR_STATUS] &= ~errorBit;
        modified[REG_ERROR_STATUS] = true;
    }
    
    /**
     * Checks if register has been modified.
     * 
     * @param reg Register index
     * @return true if register was modified
     * @throws IllegalArgumentException if register index is invalid
     */
    public boolean isModified(int reg) {
        validateRegister(reg);
        return modified[reg];
    }
    
    /**
     * Resets all registers to zero and clears modification flags.
     */
    public void reset() {
        Arrays.fill(registers, 0);
        Arrays.fill(modified, false);
    }
    
    /**
     * Creates a snapshot of current register values.
     * 
     * @return Copy of register values
     */
    public long[] snapshot() {
        return registers.clone();
    }
    
    /**
     * Validates register index.
     * 
     * @param reg Register index to validate
     * @throws IllegalArgumentException if index is invalid
     */
    private void validateRegister(int reg) {
        if (reg < 0 || reg >= NUM_GP_REGISTERS) {
            throw new IllegalArgumentException(
                "Invalid register index: " + reg + 
                ". Must be between 0 and " + (NUM_GP_REGISTERS - 1));
        }
    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("BPF Registers:\n");
        
        // Standard registers
        sb.append(String.format("A  = 0x%016x %s%n", registers[REG_A], 
            modified[REG_A] ? "(M)" : ""));
        sb.append(String.format("X  = 0x%016x %s%n", registers[REG_X],
            modified[REG_X] ? "(M)" : ""));
            
        // Extended registers
        for (int i = REG_EXT_BASE; i < NUM_GP_REGISTERS; i++) {
            if (modified[i]) {
                sb.append(String.format("R%-2d= 0x%016x (M)%n", i, registers[i]));
            }
        }
        
        return sb.toString();
    }
}