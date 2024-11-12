package com.slytechs.jnet.jnetpcap.bpf.vm.util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Utility class for buffer operations.
 */
public final class BufferUtils {
    
    private BufferUtils() {
        // Prevent instantiation
    }
    
    /**
     * Creates a new buffer with network byte order (big endian).
     * 
     * @param capacity Buffer capacity
     * @return New ByteBuffer
     */
    public static ByteBuffer createBuffer(int capacity) {
        return ByteBuffer.allocate(capacity).order(ByteOrder.BIG_ENDIAN);
    }
    
    /**
     * Wraps an existing byte array in a network byte order buffer.
     * 
     * @param array Byte array to wrap
     * @return New ByteBuffer
     */
    public static ByteBuffer wrapBuffer(byte[] array) {
        return ByteBuffer.wrap(array).order(ByteOrder.BIG_ENDIAN);
    }
    
    /**
     * Safely gets a byte from a buffer.
     * 
     * @param buffer Source buffer
     * @param index Byte index
     * @return Byte value or 0 if index invalid
     */
    public static byte getByte(ByteBuffer buffer, int index) {
        return index >= 0 && index < buffer.limit() ? buffer.get(index) : 0;
    }
    
    /**
     * Safely gets a short from a buffer.
     * 
     * @param buffer Source buffer
     * @param index Byte index
     * @return Short value or 0 if index invalid
     */
    public static short getShort(ByteBuffer buffer, int index) {
        return index >= 0 && index + 1 < buffer.limit() ? buffer.getShort(index) : 0;
    }
    
    /**
     * Safely gets an int from a buffer.
     * 
     * @param buffer Source buffer
     * @param index Byte index
     * @return Int value or 0 if index invalid
     */
    public static int getInt(ByteBuffer buffer, int index) {
        return index >= 0 && index + 3 < buffer.limit() ? buffer.getInt(index) : 0;
    }
    
    /**
     * Safely gets a long from a buffer.
     * 
     * @param buffer Source buffer
     * @param index Byte index
     * @return Long value or 0 if index invalid
     */
    public static long getLong(ByteBuffer buffer, int index) {
        return index >= 0 && index + 7 < buffer.limit() ? buffer.getLong(index) : 0;
    }
    
    /**
     * Copies data between buffers safely.
     * 
     * @param src Source buffer
     * @param srcPos Source position
     * @param dst Destination buffer
     * @param dstPos Destination position
     * @param length Number of bytes to copy
     */
    public static void copyBuffer(
            ByteBuffer src, int srcPos,
            ByteBuffer dst, int dstPos,
            int length) {
        
        if (srcPos < 0 || dstPos < 0 || length < 0) {
            throw new IllegalArgumentException("Negative position or length");
        }
        
        if (srcPos + length > src.limit() || dstPos + length > dst.limit()) {
            throw new IllegalArgumentException("Copy would exceed buffer bounds");
        }
        
        for (int i = 0; i < length; i++) {
            dst.put(dstPos + i, src.get(srcPos + i));
        }
    }
}