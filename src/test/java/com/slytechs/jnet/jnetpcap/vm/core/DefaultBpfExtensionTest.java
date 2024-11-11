package com.slytechs.jnet.jnetpcap.vm.core;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.slytechs.jnet.jnetruntime.bpf.vm.api.ExecutionContext;
import com.slytechs.jnet.jnetruntime.bpf.vm.api.ExtensionContext;
import com.slytechs.jnet.jnetruntime.bpf.vm.api.ExtensionException;
import com.slytechs.jnet.jnetruntime.bpf.vm.api.ProtocolInfo;
import com.slytechs.jnet.jnetruntime.bpf.vm.core.DefaultBpfExtension;

/**
 * Test suite for DefaultBpfExtension.
 */
class DefaultBpfExtensionTest {

	private DefaultBpfExtension extension;
	private MockExtensionContext extensionContext;
	private MockExecutionContext executionContext;

	@BeforeEach
	void setup() {
		extension = new DefaultBpfExtension();
		extensionContext = new MockExtensionContext();
		executionContext = new MockExecutionContext();
	}

	@Test
	@DisplayName("Test extension initialization")
	void testInitialization() throws ExtensionException {
		// Setup
		Map<String, String> config = new HashMap<>();
		config.put("test.key", "test.value");
		extensionContext.setConfiguration(config);

		// Execute
		extension.initialize(extensionContext);

		// Verify
		assertTrue(extensionContext.getRegisteredOpcodes().contains(0x80)); // L3_CSUM
		assertTrue(extensionContext.getRegisteredOpcodes().contains(0x81)); // L4_CSUM
		assertTrue(extensionContext.getRegisteredOpcodes().contains(0x82)); // TRUNCATED
		assertEquals("Default BPF Extension", extension.getName());
		assertEquals("1.0.0", extension.getVersion());
	}

	@Test
	@DisplayName("Test double initialization throws exception")
	void testDoubleInitialization() throws ExtensionException {
		// First initialization
		extension.initialize(extensionContext);

		// Second initialization should throw
		assertThrows(ExtensionException.class, () -> extension.initialize(extensionContext));
	}

	@Test
	@DisplayName("Test Layer 3 checksum verification")
	void testLayer3Checksum() throws ExtensionException {
		// Setup
		extension.initialize(extensionContext);
		setupIPv4Packet(executionContext);

		// Execute
		boolean handled = extension.executeInstruction(0x80, 0, executionContext);

		// Verify
		assertTrue(handled);
		assertEquals(0, executionContext.getErrorType());
		// Note: Currently always returns true as it's a placeholder
	}

	@Test
	@DisplayName("Test Layer 4 TCP checksum verification")
	void testLayer4TCPChecksum() throws ExtensionException {
		// Setup
		extension.initialize(extensionContext);
		setupTCPPacket(executionContext);

		// Execute
		boolean handled = extension.executeInstruction(0x81, 0, executionContext);

		// Verify
		assertTrue(handled);
		assertEquals(0, executionContext.getErrorType());
		// Note: Currently always returns true as it's a placeholder
	}

	@Test
	@DisplayName("Test packet truncation check")
	void testTruncationCheck() throws ExtensionException {
		// Setup
		extension.initialize(extensionContext);
		setupTruncatedPacket(executionContext);

		// Execute
		boolean handled = extension.executeInstruction(0x82, 100, executionContext);

		// Verify
		assertTrue(handled);
		assertEquals(2, executionContext.getErrorType()); // ERROR_TRUNCATED
	}

	@Test
	@DisplayName("Test protocol field access")
	void testProtocolFieldAccess() throws ExtensionException {
		// Setup
		extension.initialize(extensionContext);
		setupProtocolFields(executionContext);

		// Execute - get TCP source port (layer 4, field 0)
		boolean handled = extension.executeInstruction(0x84, 0x0400, executionContext);

		// Verify
		assertTrue(handled);
		assertEquals(80, executionContext.getRegister(0)); // HTTP port
	}

	@Test
	@DisplayName("Test protocol flags check")
	void testProtocolFlags() throws ExtensionException {
		// Setup
		extension.initialize(extensionContext);
		setupProtocolFlags(executionContext);

		// Execute - check TCP flags (layer 4, ACK flag)
		boolean handled = extension.executeInstruction(0x85, 0x1004, executionContext);

		// Verify
		assertTrue(handled);
		assertEquals(1, executionContext.getRegister(0)); // Flag present
	}

	@Test
	@DisplayName("Test cleanup")
	void testCleanup() throws ExtensionException {
		// Setup
		extension.initialize(extensionContext);

		// Execute
		extension.cleanup();

		// Verify - should throw exception after cleanup
		assertThrows(ExtensionException.class, () -> extension.executeInstruction(0x80, 0, executionContext));
	}

	// Helper methods to setup test data

	private void setupIPv4Packet(MockExecutionContext context) {
		ByteBuffer packet = ByteBuffer.allocate(100);
		// Setup IPv4 header with checksum
		packet.put(0, (byte) 0x45); // Version 4, IHL 5
		packet.putShort(10, (short) 0x1234); // Checksum

		context.setPacketBuffer(packet);
		context.setProtocolInfo(3, new MockProtocolInfo(0x0800, 0, 20));
	}

	private void setupTCPPacket(MockExecutionContext context) {
		ByteBuffer packet = ByteBuffer.allocate(100);
		// Setup TCP header with checksum
		packet.putShort(16, (short) 0x5678); // Checksum

		context.setPacketBuffer(packet);
		context.setProtocolInfo(4, new MockProtocolInfo(6, 20, 20));
	}

	private void setupTruncatedPacket(MockExecutionContext context) {
		ByteBuffer packet = ByteBuffer.allocate(50);
		context.setPacketBuffer(packet);
	}

	private void setupProtocolFields(MockExecutionContext context) {
		MockProtocolInfo tcpInfo = new MockProtocolInfo(6, 20, 20);
		tcpInfo.setField(0, 80); // Source port
		context.setProtocolInfo(4, tcpInfo);
	}

	private void setupProtocolFlags(MockExecutionContext context) {
		MockProtocolInfo tcpInfo = new MockProtocolInfo(6, 20, 20);
		tcpInfo.setFlags(0x10); // ACK flag
		context.setProtocolInfo(4, tcpInfo);
	}

	// Mock classes for testing

	private static class MockExtensionContext implements ExtensionContext {
		private Map<String, String> config = new HashMap<>();
		private Set<Integer> registeredOpcodes = new HashSet<>();

		public void setConfiguration(Map<String, String> config) {
			this.config = config;
		}

		@Override
		public Map<String, String> getConfiguration() {
			return config;
		}

		@Override
		public void registerOpcode(int opcode, String name) {
			registeredOpcodes.add(opcode);
		}

		@Override
		public String getVmVersion() {
			return "1.0.0";
		}

		public Set<Integer> getRegisteredOpcodes() {
			return registeredOpcodes;
		}
	}

	private static class MockExecutionContext implements ExecutionContext {
		private ByteBuffer packet;
		private Map<Integer, ProtocolInfo> protocols = new HashMap<>();
		private Map<Integer, Long> registers = new HashMap<>();
		private int errorType;
		private long errorValue;

		public void setPacketBuffer(ByteBuffer packet) {
			this.packet = packet;
		}

		public void setProtocolInfo(int layer, ProtocolInfo info) {
			protocols.put(layer, info);
		}

		@Override
		public ByteBuffer getPacketBuffer() {
			return packet;
		}

		@Override
		public long getRegister(int register) {
			return registers.getOrDefault(register, 0L);
		}

		@Override
		public void setRegister(int register, long value) {
			registers.put(register, value);
		}

		@Override
		public void setResult(long result) {
			registers.put(-1, result);
		}

		@Override
		public ProtocolInfo getProtocolInfo(int layer) {
			return protocols.get(layer);
		}

		@Override
		public void setError(int errorType, long errorValue) {
			this.errorType = errorType;
			this.errorValue = errorValue;
		}

		public int getErrorType() {
			return errorType;
		}

		public long getErrorValue() {
			return errorValue;
		}
	}

	private static class MockProtocolInfo implements ProtocolInfo {
		private final int type;
		private final int offset;
		private final int length;
		private Map<Integer, Long> fields = new HashMap<>();
		private long flags;

		public MockProtocolInfo(int type, int offset, int length) {
			this.type = type;
			this.offset = offset;
			this.length = length;
		}

		@Override
		public int getType() {
			return type;
		}

		@Override
		public int getOffset() {
			return offset;
		}

		@Override
		public int getLength() {
			return length;
		}

		@Override
		public boolean hasField(int field) {
			return fields.containsKey(field);
		}

		@Override
		public long getField(int field) {
			return fields.getOrDefault(field, 0L);
		}

		@Override
		public long getFlags() {
			return flags;
		}

		public void setField(int field, long value) {
			fields.put(field, value);
		}

		public void setFlags(long flags) {
			this.flags = flags;
		}
	}
}