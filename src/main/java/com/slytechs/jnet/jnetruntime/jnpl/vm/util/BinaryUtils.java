package com.slytechs.jnet.jnetruntime.jnpl.vm.util;

/**
 * Utility class for binary operations and bit manipulation.
 */
public final class BinaryUtils {
    
    private BinaryUtils() {
        // Prevent instantiation
    }
    
    /**
     * Extracts bits from a value.
     * 
     * @param value Source value
     * @param offset Bit offset from right
     * @param length Number of bits to extract
     * @return Extracted bits
     */
    public static long getBits(long value, int offset, int length) {
        long mask = ((1L << length) - 1);
        return (value >>> offset) & mask;
    }
    
    /**
     * Sets bits in a value.
     * 
     * @param value Original value
     * @param bits Bits to set
     * @param offset Bit offset from right
     * @param length Number of bits to set
     * @return Modified value
     */
    public static long setBits(long value, long bits, int offset, int length) {
        long mask = ((1L << length) - 1) << offset;
        return (value & ~mask) | ((bits & ((1L << length) - 1)) << offset);
    }
    
    /**
     * Checks if a specific bit is set.
     * 
     * @param value Value to check
     * @param bitIndex Bit position (0-based from right)
     * @return true if bit is set
     */
    public static boolean isBitSet(long value, int bitIndex) {
        return (value & (1L << bitIndex)) != 0;
    }
    
    /**
     * Sets a specific bit.
     * 
     * @param value Original value
     * @param bitIndex Bit position (0-based from right)
     * @param set true to set bit, false to clear
     * @return Modified value
     */
    public static long setBit(long value, int bitIndex, boolean set) {
        if (set) {
            return value | (1L << bitIndex);
        } else {
            return value & ~(1L << bitIndex);
        }
    }
    
    /**
     * Swaps endianness of a 16-bit value.
     * 
     * @param value Value to swap
     * @return Swapped value
     */
    public static short swapShort(short value) {
        return (short) (((value & 0xFF) << 8) | ((value >> 8) & 0xFF));
    }
    
    /**
     * Swaps endianness of a 32-bit value.
     * 
     * @param value Value to swap
     * @return Swapped value
     */
    public static int swapInt(int value) {
        return ((value & 0xFF) << 24) |
               ((value & 0xFF00) << 8) |
               ((value >> 8) & 0xFF00) |
               ((value >> 24) & 0xFF);
    }
    
    /**
     * Swaps endianness of a 64-bit value.
     * 
     * @param value Value to swap
     * @return Swapped value
     */
    public static long swapLong(long value) {
        return ((value & 0xFFL) << 56) |
               ((value & 0xFF00L) << 40) |
               ((value & 0xFF0000L) << 24) |
               ((value & 0xFF000000L) << 8) |
               ((value >> 8) & 0xFF000000L) |
               ((value >> 24) & 0xFF0000L) |
               ((value >> 40) & 0xFF00L) |
               ((value >> 56) & 0xFFL);
    }
}