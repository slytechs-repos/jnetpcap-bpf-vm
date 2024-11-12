package com.slytechs.jnet.jnetpcap.bpf.vm.api;

import java.util.Map;

import com.slytechs.jnet.jnetpcap.bpf.vm.core.BpfVirtualMachine;

/**
 * Factory for creating BPF VM instances.
 */
public interface BpfVmFactory {

	/**
	 * Creates a new VM instance.
	 * 
	 * @return New VM instance
	 */
	BpfVirtualMachine createVm();

	/**
	 * Creates a new VM instance with configuration.
	 * 
	 * @param config Configuration map
	 * @return New VM instance
	 * @throws ExtensionConfigException if configuration is invalid
	 */
	BpfVirtualMachine createVm(Map<String, String> config)
			throws ExtensionConfigException;

	/**
	 * Gets factory version.
	 * 
	 * @return Version string
	 */
	String getVersion();

	/**
	 * Gets supported extensions.
	 * 
	 * @return Array of supported extension names
	 */
	String[] getSupportedExtensions();
}