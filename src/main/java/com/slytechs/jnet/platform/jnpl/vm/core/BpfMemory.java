package com.slytechs.jnet.platform.jnpl.vm.core;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Manages memory access for BPF VM packet data processing.
 * Provides safe access to packet data with bounds checking and
 * supports different endianness for network protocol parsing.
 */
public class BpfMemory {
    
    /** Default packet buffer size */
    private static final int DEFAULT_BUFFER_SIZE = 65536;
    
    /** Maximum allowed packet size */
    private static final int MAX_PACKET_SIZE = 1024 * 1024; // 1MB
    
    /** Packet data buffer */
    private ByteBuffer buffer;
    
    /** Current packet length */
    private int packetLength;
    
    /** Whether memory has been initialized */
    private boolean initialized;
    
    /** Track if packet was truncated */
    private boolean truncated;
    
    /** Original packet length before truncation */
    private int originalLength;
    
    /**
     * Creates a new BPF memory manager with default buffer size.
     */
    public BpfMemory() {
        this(DEFAULT_BUFFER_SIZE);
    }
    
    /**
     * Creates a new BPF memory manager with specified buffer size.
     * 
     * @param bufferSize Initial buffer size
     * @throws IllegalArgumentException if size exceeds maximum
     */
    public BpfMemory(int bufferSize) {
        if (bufferSize > MAX_PACKET_SIZE) {
            throw new IllegalArgumentException(
                "Buffer size exceeds maximum allowed: " + MAX_PACKET_SIZE);
        }
        this.buffer = ByteBuffer.allocate(bufferSize);
        this.buffer.order(ByteOrder.BIG_ENDIAN); // Network byte order
        this.initialized = false;
    }
    
    /**
     * Loads packet data for processing.
     * 
     * @param data Packet data buffer
     * @param offset Start offset in data
     * @param length Length of packet data
     * @throws IllegalArgumentException if length exceeds maximum
     */
    public void loadPacket(byte[] data, int offset, int length) {
        if (length > MAX_PACKET_SIZE) {
            throw new IllegalArgumentException(
                "Packet size exceeds maximum allowed: " + MAX_PACKET_SIZE);
        }
        
        ensureCapacity(length);
        buffer.clear();
        buffer.put(data, offset, length);
        buffer.flip();
        
        this.packetLength = length;
        this.originalLength = length;
        this.truncated = false;
        this.initialized = true;
    }
    
    /**
     * Loads packet data from a ByteBuffer.
     * 
     * @param src Source buffer containing packet data
     * @throws IllegalArgumentException if length exceeds maximum
     */
    public void loadPacket(ByteBuffer src) {
        int length = src.remaining();
        if (length > MAX_PACKET_SIZE) {
            throw new IllegalArgumentException(
                "Packet size exceeds maximum allowed: " + MAX_PACKET_SIZE);
        }
        
        ensureCapacity(length);
        buffer.clear();
        buffer.put(src);
        buffer.flip();
        
        this.packetLength = length;
        this.originalLength = length;
        this.truncated = false;
        this.initialized = true;
    }
    
    /**
     * Reads a byte from the specified offset.
     * 
     * @param offset Memory offset
     * @return Byte value at offset
     * @throws BpfMemoryAccessException if access is invalid
     */
    public byte readByte(int offset) {
        checkInitialized();
        checkBounds(offset, 1);
        return buffer.get(offset);
    }
    
    /**
     * Reads a 16-bit value from the specified offset.
     * 
     * @param offset Memory offset
     * @return Short value at offset
     * @throws BpfMemoryAccessException if access is invalid
     */
    public short readShort(int offset) {
        checkInitialized();
        checkBounds(offset, 2);
        return buffer.getShort(offset);
    }
    
    /**
     * Reads a 32-bit value from the specified offset.
     * 
     * @param offset Memory offset
     * @return Integer value at offset
     * @throws BpfMemoryAccessException if access is invalid
     */
    public int readInt(int offset) {
        checkInitialized();
        checkBounds(offset, 4);
        return buffer.getInt(offset);
    }
    
    /**
     * Reads a 64-bit value from the specified offset.
     * 
     * @param offset Memory offset
     * @return Long value at offset
     * @throws BpfMemoryAccessException if access is invalid
     */
    public long readLong(int offset) {
        checkInitialized();
        checkBounds(offset, 8);
        return buffer.getLong(offset);
    }
    
    /**
     * Sets the byte order for value reading.
     * 
     * @param order Byte order (BIG_ENDIAN or LITTLE_ENDIAN)
     */
    public void setByteOrder(ByteOrder order) {
        buffer.order(order);
    }
    
    /**
     * Gets the current packet length.
     * 
     * @return Current packet length
     */
    public int getPacketLength() {
        return packetLength;
    }
    
    /**
     * Gets the original packet length before any truncation.
     * 
     * @return Original packet length
     */
    public int getOriginalLength() {
        return originalLength;
    }
    
    /**
     * Checks if the packet was truncated.
     * 
     * @return true if packet was truncated
     */
    public boolean isTruncated() {
        return truncated;
    }
    
    /**
     * Sets truncation status and updates lengths.
     * 
     * @param newLength New truncated length
     */
    public void setTruncated(int newLength) {
        if (newLength < packetLength) {
            this.truncated = true;
            this.packetLength = newLength;
        }
    }
    
    /**
     * Ensures buffer has sufficient capacity.
     * 
     * @param required Required capacity
     */
    private void ensureCapacity(int required) {
        if (buffer.capacity() < required) {
            ByteBuffer newBuffer = ByteBuffer.allocate(required);
            newBuffer.order(buffer.order());
            buffer = newBuffer;
        }
    }
    
    /**
     * Validates memory is initialized.
     * 
     * @throws BpfMemoryAccessException if memory not initialized
     */
    private void checkInitialized() {
        if (!initialized) {
            throw new BpfMemoryAccessException("Memory not initialized with packet data");
        }
    }
    
    /**
     * Validates memory access bounds.
     * 
     * @param offset Start offset
     * @param size Access size
     * @throws BpfMemoryAccessException if access would be out of bounds
     */
    private void checkBounds(int offset, int size) {
        if (offset < 0 || offset + size > packetLength) {
            throw new BpfMemoryAccessException(
                String.format("Memory access out of bounds: offset=%d, size=%d, length=%d",
                    offset, size, packetLength));
        }
    }
    
    /**
     * Exception thrown for invalid memory access.
     */
    public static class BpfMemoryAccessException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        
        public BpfMemoryAccessException(String message) {
            super(message);
        }
    }
    
    /**
     * Gets a read-only view of the current packet data.
     * 
     * @return Read-only ByteBuffer
     */
    public ByteBuffer getReadOnlyBuffer() {
        return buffer.asReadOnlyBuffer();
    }
    
    /**
     * Resets the memory manager state.
     */
    public void reset() {
        buffer.clear();
        packetLength = 0;
        originalLength = 0;
        truncated = false;
        initialized = false;
    }
}