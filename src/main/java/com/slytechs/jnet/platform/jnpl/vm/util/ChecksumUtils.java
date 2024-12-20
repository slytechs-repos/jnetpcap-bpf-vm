package com.slytechs.jnet.platform.jnpl.vm.util;

import java.nio.ByteBuffer;

/**
 * Utility class for calculating network checksums.
 */
public final class ChecksumUtils {
    
    private ChecksumUtils() {
        // Prevent instantiation
    }
    
    /**
     * Calculates Internet checksum over a byte array.
     * 
     * @param data Data to checksum
     * @param offset Start offset
     * @param length Length of data
     * @return Computed checksum
     */
    public static int calculateChecksum(byte[] data, int offset, int length) {
        long sum = 0;
        int i = 0;
        
        // Handle pairs of bytes
        while (i < length - 1) {
            sum += (((data[offset + i] & 0xFF) << 8) | (data[offset + i + 1] & 0xFF)) & 0xFFFF;
            if ((sum & 0xFFFF0000) > 0) {
                sum = (sum & 0xFFFF) + 1;
            }
            i += 2;
        }
        
        // Handle odd byte if present
        if (i < length) {
            sum += (data[offset + i] & 0xFF) << 8;
            if ((sum & 0xFFFF0000) > 0) {
                sum = (sum & 0xFFFF) + 1;
            }
        }
        
        return ~((int)sum & 0xFFFF);
    }
    
    /**
     * Calculates Internet checksum over a ByteBuffer.
     * 
     * @param buffer Buffer containing data
     * @param offset Start offset
     * @param length Length of data
     * @return Computed checksum
     */
    public static int calculateChecksum(ByteBuffer buffer, int offset, int length) {
        buffer.position(offset);
        long sum = 0;
        
        // Handle complete words
        while (length > 1) {
            sum += buffer.getShort() & 0xFFFF;
            if ((sum & 0xFFFF0000) > 0) {
                sum = (sum & 0xFFFF) + 1;
            }
            length -= 2;
        }
        
        // Handle odd byte if present
        if (length > 0) {
            sum += (buffer.get() & 0xFF) << 8;
            if ((sum & 0xFFFF0000) > 0) {
                sum = (sum & 0xFFFF) + 1;
            }
        }
        
        return ~((int)sum & 0xFFFF);
    }
    
    /**
     * Verifies TCP/UDP checksum.
     * 
     * @param buffer Packet data
     * @param ipOffset IP header offset
     * @param protocolOffset Protocol header offset
     * @param isIPv6 true if IPv6, false if IPv4
     * @return true if checksum is valid
     */
    public static boolean verifyTransportChecksum(
            ByteBuffer buffer, int ipOffset, int protocolOffset, boolean isIPv6) {
        // Implementation dependent on protocol details
        // This is a placeholder for the actual implementation
        return true;
    }
}