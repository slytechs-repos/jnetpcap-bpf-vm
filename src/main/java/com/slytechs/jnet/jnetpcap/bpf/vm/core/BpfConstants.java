package com.slytechs.jnet.jnetpcap.bpf.vm.core;

/**
 * Shared constants for BPF VM implementation
 */
public interface BpfConstants {
	/** Maximum number of protocol layers */
	int MAX_PROTOCOL_LAYERS = 16;

	/** Maximum packet size */
	int MAX_PACKET_SIZE = 1024 * 1024; // 1MB

	/** Default packet buffer size */
	int DEFAULT_BUFFER_SIZE = 65536;

	/** Maximum program length */
	int MAX_PROGRAM_LENGTH = 4096;

	/** Maximum execution steps */
	int MAX_EXECUTION_STEPS = 1024 * 1024;
}