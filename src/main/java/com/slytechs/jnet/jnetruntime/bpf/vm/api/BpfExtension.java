package com.slytechs.jnet.jnetruntime.bpf.vm.api;

/**
 * Service provider interface for BPF VM extensions.
 * Allows adding custom functionality to the VM.
 */
public interface BpfExtension {
    
    /**
     * Gets the extension name.
     * 
     * @return Extension name
     */
    String getName();
    
    /**
     * Gets the extension version.
     * 
     * @return Extension version
     */
    String getVersion();
    
    /**
     * Initializes the extension.
     * 
     * @param context Extension initialization context
     * @throws ExtensionException if initialization fails
     */
    void initialize(ExtensionContext context) throws ExtensionException;
    
    /**
     * Executes an extension instruction.
     * 
     * @param opcode Extension opcode
     * @param immediate Immediate value
     * @param context Execution context
     * @return true if instruction was handled
     * @throws ExtensionException if execution fails
     */
    boolean executeInstruction(int opcode, int immediate, 
                             ExecutionContext context) throws ExtensionException;
    
    /**
     * Cleans up extension resources.
     */
    void cleanup();
}