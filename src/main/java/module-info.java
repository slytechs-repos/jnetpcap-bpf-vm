/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
 *
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
/**
 * Berkeley Packet Filter (BPF) Virtual Machine implementation module. This
 * module provides a Java-based implementation of the BPF instruction set and
 * virtual machine, compatible with tcpdump/libpcap filter programs.
 * <p>
 * The module includes:
 * <ul>
 * <li>BPF instruction set implementation</li>
 * <li>Virtual machine for executing BPF programs</li>
 * <li>Program loader and validator</li>
 * <li>Tcpdump compatibility layer</li>
 * <li>Extension mechanism for custom functionality</li>
 * </ul>
 * 
 * @provides com.slytechs.jnet.platform.jnpl.vm.api.BpfExtension Extension
 *           point for adding custom BPF functionality
 * 
 * @uses com.slytechs.jnet.platform.jnpl.vm.api.BpfExtension Service interface
 *       for BPF extensions
 * 
 * @see com.slytechs.jnet.platform.jnpl.vm.core.BpfVirtualMachine
 * @see com.slytechs.jnet.platform.jnpl.vm.core.BpfProgram
 * @see com.slytechs.jnet.platform.jnpl.vm.instruction.BpfOpcode
 * 
 * @author Sly Technologies Inc
 * @version 1.0
 */
module com.slytechs.jnet.platform.jnpl {

	/**
	 * Core Java runtime dependency. Required for basic Java functionality including
	 * NIO buffers and standard collections.
	 */
	requires java.base;
	requires com.slytechs.jnet.platform.api;

	/**
	 * Core VM implementation package. Contains the main virtual machine
	 * implementation, program representation, and execution context.
	 */
	exports com.slytechs.jnet.platform.jnpl.vm.core;

	/**
	 * Instruction set definition package. Contains BPF instruction definitions,
	 * opcodes, and related constant values.
	 */
	exports com.slytechs.jnet.platform.jnpl.vm.instruction;

	/**
	 * Public API package. Contains interfaces and classes intended for public use
	 * and extension.
	 */
	exports com.slytechs.jnet.platform.jnpl.vm.api;

	/**
	 * Utility classes package. Contains helper classes, data structures, and common
	 * functionality used across the module.
	 */
	exports com.slytechs.jnet.platform.jnpl.vm.util;

	/**
	 * Development and debugging tools package. Restricted export to specific tool
	 * and debug modules. Contains program analysis, debugging, and development
	 * tools.
	 */
	exports com.slytechs.jnet.platform.jnpl.vm.tools to
			com.slytechs.jnet.jnetpcap.debug,
			com.slytechs.jnet.jnetpcap.tools;

	/**
	 * Test access configuration. Opens core packages for reflection access during
	 * testing. This allows test frameworks to access and verify internal state.
	 */
	opens com.slytechs.jnet.platform.jnpl.vm.core to
			com.slytechs.jnet.jnetpcap.test;

	/**
	 * Extension point service interface. Declares the use of the BpfExtension
	 * service interface for runtime extension of VM functionality.
	 */
	uses com.slytechs.jnet.platform.jnpl.vm.api.BpfExtension;

	/**
	 * Default extension provider. Registers the default implementation of the
	 * BpfExtension service interface providing basic VM extensions.
	 */
	provides com.slytechs.jnet.platform.jnpl.vm.api.BpfExtension with
			com.slytechs.jnet.platform.jnpl.vm.core.DefaultBpfExtension;
}