package com.slytechs.jnet.jnetruntime.bpf.vm.core;

import java.nio.ByteBuffer;

import com.slytechs.jnet.jnetruntime.bpf.vm.core.BpfInterpreter.BpfExecutionException;
import com.slytechs.jnet.jnetruntime.bpf.vm.instruction.BpfOpcode;

/**
 * Top-level BPF virtual machine implementation. Coordinates program loading,
 * validation, and execution.
 */
public class BpfVirtualMachine {

	/** The execution context */
	private final BpfContext context;

	/** The instruction interpreter */
	private final BpfInterpreter interpreter;

	/** Currently loaded program */
	private BpfProgram currentProgram;

	/** Program validator */
	private final BpfProgramValidator validator;

	/**
	 * Creates a new BPF virtual machine.
	 */
	public BpfVirtualMachine() {
		this(new BpfContext());
	}

	/**
	 * Creates a new BPF virtual machine with specified memory size.
	 * 
	 * @param memorySize Size of packet buffer
	 */
	public BpfVirtualMachine(int memorySize) {
		this(new BpfContext(memorySize));
	}

	/**
	 * Creates a new BPF virtual machine with specified context.
	 * 
	 * @param context Execution context
	 */
	public BpfVirtualMachine(BpfContext context) {
		this.context = context;
		this.interpreter = new BpfInterpreter();
		this.validator = new BpfProgramValidator();
	}

	/**
	 * Loads and validates a BPF program.
	 * 
	 * @param program Program to load
	 * @throws BpfValidationException if program is invalid
	 */
	public void loadProgram(BpfProgram program) {
		ValidationResult result = validator.validate(program);
		if (!result.isValid()) {
			throw new BpfValidationException("Program validation failed: " + result.getErrorMessage());
		}

		program.setValidationStatus(true, null);
		this.currentProgram = program;
	}

	/**
	 * Loads and validates a BPF program from raw instructions.
	 * 
	 * @param instructions Raw instruction array
	 * @throws BpfValidationException if program is invalid
	 */
	public void loadProgram(long[] instructions) {
		loadProgram(BpfProgram.fromRawInstructions(instructions));
	}

	/**
	 * Executes the loaded program against a packet.
	 * 
	 * @param packet Packet data
	 * @param offset Start offset in packet data
	 * @param length Length of packet data
	 * @return Execution result
	 * @throws BpfExecutionException if execution fails
	 */
	public long execute(byte[] packet, int offset, int length) {
		if (currentProgram == null) {
			throw new BpfExecutionException("No program loaded");
		}

		try {
			context.getMemory().loadPacket(packet, offset, length);
			return interpreter.execute(currentProgram, context);
		} catch (Exception e) {
			throw new BpfExecutionException("Execution failed: " + e.getMessage(), e);
		}
	}

	/**
	 * Executes the loaded program against a packet in a ByteBuffer.
	 * 
	 * @param packet Packet data buffer
	 * @return Execution result
	 * @throws BpfExecutionException if execution fails
	 */
	public long execute(ByteBuffer packet) {
		if (currentProgram == null) {
			throw new BpfExecutionException("No program loaded");
		}

		try {
			context.getMemory().loadPacket(packet);
			return interpreter.execute(currentProgram, context);
		} catch (Exception e) {
			throw new BpfExecutionException("Execution failed: " + e.getMessage(), e);
		}
	}

	/**
	 * Gets the current execution context.
	 * 
	 * @return BpfContext instance
	 */
	public BpfContext getContext() {
		return context;
	}

	/**
	 * Gets the currently loaded program.
	 * 
	 * @return Current BpfProgram or null if none loaded
	 */
	public BpfProgram getCurrentProgram() {
		return currentProgram;
	}

	/**
	 * Resets the virtual machine state.
	 */
	public void reset() {
		context.reset();
		currentProgram = null;
	}

	/**
	 * Program validator implementation.
	 */
	private static class BpfProgramValidator {

		/**
		 * Validates a BPF program.
		 * 
		 * @param program Program to validate
		 * @return Validation result
		 */
		public ValidationResult validate(BpfProgram program) {
			try {
				// Check program length
				if (program.getLength() == 0) {
					return new ValidationResult(false, "Empty program");
				}

				// Check termination
				if (!hasValidTermination(program)) {
					return new ValidationResult(false, "Program lacks valid termination");
				}

				// Check jump targets
				if (!hasValidJumps(program)) {
					return new ValidationResult(false, "Invalid jump targets");
				}

				// Check division by zero
				if (!hasValidDivisions(program)) {
					return new ValidationResult(false, "Potential division by zero");
				}

				// Check memory access
				if (!hasValidMemoryAccess(program)) {
					return new ValidationResult(false, "Invalid memory access");
				}

				return new ValidationResult(true, null);

			} catch (Exception e) {
				return new ValidationResult(false, "Validation error: " + e.getMessage());
			}
		}

		private boolean hasValidTermination(BpfProgram program) {
			// Check if program ends with RET instruction
			BpfInstruction lastInst = program.getInstruction(program.getLength() - 1);
			return lastInst.getOpcodeEnum().isReturn();
		}

		private boolean hasValidJumps(BpfProgram program) {
			for (int i = 0; i < program.getLength(); i++) {
				BpfInstruction inst = program.getInstruction(i);
				if (inst.getOpcodeEnum().isJump()) {
					if (inst.getOpcodeEnum() == BpfOpcode.JMP_JA) {
						// Unconditional jump uses relative offset
						int target = i + 1 + inst.getImmediate();
						if (target < 0 || target >= program.getLength()) {
							return false;
						}
					} else {
						// Conditional jumps in tcpdump format use absolute targets
						int jtrue = inst.getDst();
						int jfalse = inst.getSrc();

						if (jtrue >= program.getLength() || jfalse >= program.getLength()) {
							return false;
						}
					}
				}
			}
			return true;
		}

		private boolean hasValidDivisions(BpfProgram program) {
			for (int i = 0; i < program.getLength(); i++) {
				BpfInstruction inst = program.getInstruction(i);
				BpfOpcode opcode = inst.getOpcodeEnum();

				// Check immediate division by zero
				if (opcode == BpfOpcode.DIV_K && inst.getImmediate() == 0) {
					return false;
				}
			}
			return true;
		}

		private boolean hasValidMemoryAccess(BpfProgram program) {
			for (int i = 0; i < program.getLength(); i++) {
				BpfInstruction inst = program.getInstruction(i);
				BpfOpcode opcode = inst.getOpcodeEnum();

				if (opcode.isLoad() || opcode.isStore()) {
					// Check for obviously invalid memory addresses
					if (inst.getImmediate() < 0) {
						return false;
					}
				}
			}
			return true;
		}
	}

	/**
	 * Program validation result.
	 */
	private static class ValidationResult {
		private final boolean valid;
		private final String errorMessage;

		public ValidationResult(boolean valid, String errorMessage) {
			this.valid = valid;
			this.errorMessage = errorMessage;
		}

		public boolean isValid() {
			return valid;
		}

		public String getErrorMessage() {
			return errorMessage;
		}
	}

	/**
	 * Exception thrown for program validation errors.
	 */
	public static class BpfValidationException extends RuntimeException {
		private static final long serialVersionUID = 1L;

		public BpfValidationException(String message) {
			super(message);
		}

		public BpfValidationException(String message, Throwable cause) {
			super(message, cause);
		}
	}
}