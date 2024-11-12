package com.slytechs.jnet.jnetpcap.bpf.vm.util;

/**
 * Utility class for handling hexadecimal conversions and formatting.
 */
public final class HexUtils {
    
    private HexUtils() {
        // Prevent instantiation
    }
    
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    
    /**
     * Converts a byte array to a hexadecimal string.
     * 
     * @param bytes Byte array to convert
     * @return Hexadecimal string representation
     */
    public static String toHexString(byte[] bytes) {
        return toHexString(bytes, 0, bytes.length);
    }
    
    /**
     * Converts a portion of a byte array to a hexadecimal string.
     * 
     * @param bytes Byte array to convert
     * @param offset Start offset
     * @param length Number of bytes to convert
     * @return Hexadecimal string representation
     */
    public static String toHexString(byte[] bytes, int offset, int length) {
        char[] hexChars = new char[length * 2];
        for (int i = 0; i < length; i++) {
            int v = bytes[offset + i] & 0xFF;
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
    
    /**
     * Formats a long value as a hexadecimal string with leading zeros.
     * 
     * @param value Value to format
     * @param width Minimum number of digits
     * @return Formatted hexadecimal string
     */
    public static String toHexString(long value, int width) {
        return String.format("%0" + width + "X", value);
    }
    
    /**
     * Parses a hexadecimal string into a byte array.
     * 
     * @param hex Hexadecimal string
     * @return Byte array
     * @throws IllegalArgumentException if string has invalid format
     */
    public static byte[] fromHexString(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }
        
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            int high = Character.digit(hex.charAt(i * 2), 16);
            int low = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (high == -1 || low == -1) {
                throw new IllegalArgumentException("Invalid hex character");
            }
            result[i] = (byte) ((high << 4) | low);
        }
        return result;
    }
}