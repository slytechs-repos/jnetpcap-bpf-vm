package com.slytechs.jnet.jnetruntime.jnpl.vm.api;

import java.util.Map;

/**
 * Context for extension initialization.
 */
public interface ExtensionContext {
    
    /**
     * Gets extension configuration.
     * 
     * @return Configuration map
     */
    Map<String, String> getConfiguration();
    
    /**
     * Registers an extension opcode.
     * 
     * @param opcode Opcode value
     * @param name Opcode name
     * @throws ExtensionException if registration fails
     */
    void registerOpcode(int opcode, String name) throws ExtensionException;
    
    /**
     * Gets the VM version.
     * 
     * @return VM version string
     */
    String getVmVersion();
}
