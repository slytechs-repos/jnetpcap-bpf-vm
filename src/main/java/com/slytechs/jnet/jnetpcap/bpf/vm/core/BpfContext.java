package com.slytechs.jnet.jnetpcap.bpf.vm.core;

/**
 * Represents the execution context for BPF program execution.
 * Maintains state across instruction execution including registers,
 * memory access, and program counter.
 */
public class BpfContext {
    
    /** The register file */
    private final BpfRegisters registers;
    
    /** The memory manager */
    private final BpfMemory memory;
    
    /** Program counter */
    private int programCounter;
    
    /** Execution result (for early termination) */
    private long result;
    
    /** Whether execution should terminate */
    private boolean terminated;
    
    /** Protocol header offsets */
    private final int[] protocolOffsets;
    
    /** Maximum number of protocol layers */
    private static final int MAX_PROTOCOL_LAYERS = 16;
    
    /** Layer classification results */
    private final int[] layerTypes;
    
    /** Protocol lookup table */
    private final ProtocolTable protocolTable;
    
    /**
     * Creates a new BPF execution context.
     */
    public BpfContext() {
        this.registers = new BpfRegisters();
        this.memory = new BpfMemory();
        this.protocolOffsets = new int[MAX_PROTOCOL_LAYERS];
        this.layerTypes = new int[MAX_PROTOCOL_LAYERS];
        this.protocolTable = new ProtocolTable();
        reset();
    }
    
    /**
     * Creates a new BPF execution context with specified memory size.
     * 
     * @param memorySize Size of packet buffer
     */
    public BpfContext(int memorySize) {
        this.registers = new BpfRegisters();
        this.memory = new BpfMemory(memorySize);
        this.protocolOffsets = new int[MAX_PROTOCOL_LAYERS];
        this.layerTypes = new int[MAX_PROTOCOL_LAYERS];
        this.protocolTable = new ProtocolTable();
        reset();
    }
    
    /**
     * Gets the register file.
     * 
     * @return BpfRegisters instance
     */
    public BpfRegisters getRegisters() {
        return registers;
    }
    
    /**
     * Gets the memory manager.
     * 
     * @return BpfMemory instance
     */
    public BpfMemory getMemory() {
        return memory;
    }
    
    /**
     * Gets the current program counter.
     * 
     * @return Program counter value
     */
    public int getProgramCounter() {
        return programCounter;
    }
    
    /**
     * Sets the program counter.
     * 
     * @param pc New program counter value
     */
    public void setProgramCounter(int pc) {
        this.programCounter = pc;
    }
    
    /**
     * Increments the program counter.
     */
    public void incrementProgramCounter() {
        programCounter++;
    }
    
    /**
     * Gets the execution result.
     * 
     * @return Execution result value
     */
    public long getResult() {
        return result;
    }
    
    /**
     * Sets the execution result and marks execution as terminated.
     * 
     * @param result Result value
     */
    public void setResult(long result) {
        this.result = result;
        this.terminated = true;
    }
    
    /**
     * Checks if execution should terminate.
     * 
     * @return true if execution should stop
     */
    public boolean isTerminated() {
        return terminated;
    }
    
    /**
     * Sets a protocol offset.
     * 
     * @param layer Protocol layer index
     * @param offset Offset value
     * @throws IllegalArgumentException if layer is invalid
     */
    public void setProtocolOffset(int layer, int offset) {
        if (layer < 0 || layer >= MAX_PROTOCOL_LAYERS) {
            throw new IllegalArgumentException("Invalid protocol layer: " + layer);
        }
        protocolOffsets[layer] = offset;
        
        // Update register for quick access
        if (layer <= 4) { // Update for important layers
            registers.set(BpfRegisters.REG_L3_OFFSET + layer - 3, offset);
        }
    }
    
    /**
     * Gets a protocol offset.
     * 
     * @param layer Protocol layer index
     * @return Offset value
     * @throws IllegalArgumentException if layer is invalid
     */
    public int getProtocolOffset(int layer) {
        if (layer < 0 || layer >= MAX_PROTOCOL_LAYERS) {
            throw new IllegalArgumentException("Invalid protocol layer: " + layer);
        }
        return protocolOffsets[layer];
    }
    
    /**
     * Sets a layer type.
     * 
     * @param layer Protocol layer index
     * @param type Protocol type
     * @throws IllegalArgumentException if layer is invalid
     */
    public void setLayerType(int layer, int type) {
        if (layer < 0 || layer >= MAX_PROTOCOL_LAYERS) {
            throw new IllegalArgumentException("Invalid protocol layer: " + layer);
        }
        layerTypes[layer] = type;
    }
    
    /**
     * Gets a layer type.
     * 
     * @param layer Protocol layer index
     * @return Protocol type
     * @throws IllegalArgumentException if layer is invalid
     */
    public int getLayerType(int layer) {
        if (layer < 0 || layer >= MAX_PROTOCOL_LAYERS) {
            throw new IllegalArgumentException("Invalid protocol layer: " + layer);
        }
        return layerTypes[layer];
    }
    
    /**
     * Gets the protocol table.
     * 
     * @return ProtocolTable instance
     */
    public ProtocolTable getProtocolTable() {
        return protocolTable;
    }
    
    /**
     * Resets the execution context to initial state.
     */
    public void reset() {
        registers.reset();
        memory.reset();
        programCounter = 0;
        result = 0;
        terminated = false;
        
        // Reset protocol state
        for (int i = 0; i < MAX_PROTOCOL_LAYERS; i++) {
            protocolOffsets[i] = 0;
            layerTypes[i] = 0;
        }
    }
    
    /**
     * Protocol identification and management.
     */
    public static class ProtocolTable {
        // Protocol type constants
        public static final int PROTO_UNKNOWN = 0;
        public static final int PROTO_IPV4 = 1;
        public static final int PROTO_IPV6 = 2;
        public static final int PROTO_TCP = 3;
        public static final int PROTO_UDP = 4;
        public static final int PROTO_ICMP = 5;
        public static final int PROTO_SCTP = 6;
        
        /**
         * Gets protocol type from identifier.
         * 
         * @param id Protocol identifier (e.g., IP protocol number)
         * @return Protocol type constant
         */
        public int getProtocolType(int id) {
            // Map protocol numbers to internal types
            switch (id) {
                case 4:   return PROTO_IPV4;
                case 6:   return PROTO_TCP;
                case 17:  return PROTO_UDP;
                case 1:   return PROTO_ICMP;
                case 132: return PROTO_SCTP;
                case 41:  return PROTO_IPV6;
                default:  return PROTO_UNKNOWN;
            }
        }
        
        /**
         * Checks if protocol type is IP (v4 or v6).
         * 
         * @param type Protocol type
         * @return true if IP protocol
         */
        public boolean isIpProtocol(int type) {
            return type == PROTO_IPV4 || type == PROTO_IPV6;
        }
        
        /**
         * Checks if protocol type is transport layer.
         * 
         * @param type Protocol type
         * @return true if transport protocol
         */
        public boolean isTransportProtocol(int type) {
            return type == PROTO_TCP || type == PROTO_UDP || 
                   type == PROTO_SCTP || type == PROTO_ICMP;
        }
    }
}