package com.slytechs.jnet.jnetruntime.bpf.vm.api;

/**
 * Protocol layer information.
 */
public interface ProtocolInfo {
    
    /**
     * Gets protocol type.
     * 
     * @return Protocol type identifier
     */
    int getType();
    
    /**
     * Gets protocol offset in packet.
     * 
     * @return Offset in bytes
     */
    int getOffset();
    
    /**
     * Gets protocol header length.
     * 
     * @return Length in bytes
     */
    int getLength();
    
    /**
     * Checks if protocol has specific field.
     * 
     * @param field Field identifier
     * @return true if field exists
     */
    boolean hasField(int field);
    
    /**
     * Gets field value.
     * 
     * @param field Field identifier
     * @return Field value
     * @throws IllegalArgumentException if field not found
     */
    long getField(int field);
    
    /**
     * Gets protocol flags.
     * 
     * @return Protocol flags
     */
    long getFlags();
}