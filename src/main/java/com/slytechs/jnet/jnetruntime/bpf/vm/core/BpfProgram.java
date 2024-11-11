package com.slytechs.jnet.jnetruntime.bpf.vm.core;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Iterator;

/**
 * Represents a compiled BPF program containing a sequence of instructions. The
 * program maintains state about instruction count, validation status, and
 * provides safe access to its instructions.
 */
public class BpfProgram implements Iterable<BpfInstruction> {

	/** Maximum allowed instructions in a single program */
	private static final int MAX_INSTRUCTIONS = 4096;

	/** Array of instructions comprising the program */
	private final BpfInstruction[] instructions;

	/** Number of instructions in the program */
	private final int length;

	/** Program validation status */
	private boolean validated;

	/** Program validation error message if any */
	private String validationError;

	/**
	 * Creates a new BPF program from an array of instructions.
	 * 
	 * @param instructions Array of BPF instructions
	 * @throws IllegalArgumentException if instructions exceed maximum length
	 */
	public BpfProgram(BpfInstruction[] instructions) {
		if (instructions.length > MAX_INSTRUCTIONS) {
			throw new IllegalArgumentException(
					"Program exceeds maximum instruction limit of " + MAX_INSTRUCTIONS);
		}
		this.instructions = instructions.clone();
		this.length = instructions.length;
		this.validated = false;
	}

	/**
	 * Creates a new BPF program from raw instruction data.
	 * 
	 * @param rawInstructions Array of 64-bit raw instructions
	 * @throws IllegalArgumentException if instructions exceed maximum length
	 */
	public static BpfProgram fromRawInstructions(long[] rawInstructions) {
		BpfInstruction[] instructions = new BpfInstruction[rawInstructions.length];
		for (int i = 0; i < rawInstructions.length; i++) {
			instructions[i] = new BpfInstruction(rawInstructions[i]);
		}
		return new BpfProgram(instructions);
	}

	/**
	 * Creates a BPF program from a ByteBuffer containing raw instructions.
	 * 
	 * @param buffer ByteBuffer containing 64-bit instructions
	 * @return New BPF program
	 * @throws IllegalArgumentException if buffer size is not multiple of 8
	 */
	public static BpfProgram fromByteBuffer(ByteBuffer buffer) {
		if (buffer.remaining() % 8 != 0) {
			throw new IllegalArgumentException("Buffer must contain complete 64-bit instructions");
		}

		int numInstructions = buffer.remaining() / 8;
		long[] rawInstructions = new long[numInstructions];

		for (int i = 0; i < numInstructions; i++) {
			rawInstructions[i] = buffer.getLong();
		}

		return fromRawInstructions(rawInstructions);
	}

	/**
	 * Gets the instruction at the specified program counter.
	 * 
	 * @param pc Program counter (instruction index)
	 * @return The instruction at that position
	 * @throws IndexOutOfBoundsException if pc is invalid
	 */
	public BpfInstruction getInstruction(int pc) {
		if (pc < 0 || pc >= length) {
			throw new IndexOutOfBoundsException("Invalid program counter: " + pc);
		}
		return instructions[pc];
	}

	/**
	 * Gets the number of instructions in the program.
	 * 
	 * @return Program length
	 */
	public int getLength() {
		return length;
	}

	/**
	 * Checks if the program has been validated.
	 * 
	 * @return true if program has been validated
	 */
	public boolean isValidated() {
		return validated;
	}

	/**
	 * Gets any validation error message.
	 * 
	 * @return Validation error message or null if none
	 */
	public String getValidationError() {
		return validationError;
	}

	/**
	 * Sets the validation status and error message.
	 * 
	 * @param validated Whether program passed validation
	 * @param error     Error message if validation failed
	 */
	public void setValidationStatus(boolean validated, String error) {
		this.validated = validated;
		this.validationError = error;
	}

	/**
	 * Converts program to raw instruction array.
	 * 
	 * @return Array of raw 64-bit instructions
	 */
	public long[] toRawInstructions() {
		long[] raw = new long[length];
		for (int i = 0; i < length; i++) {
			raw[i] = instructions[i].getRawInstruction();
		}
		return raw;
	}

	/**
	 * Writes program to a ByteBuffer.
	 * 
	 * @param buffer Target buffer to write to
	 * @throws IllegalArgumentException if buffer has insufficient space
	 */
	public void writeToBuffer(ByteBuffer buffer) {
		if (buffer.remaining() < length * 8) {
			throw new IllegalArgumentException("Insufficient buffer space");
		}

		for (BpfInstruction inst : instructions) {
			buffer.putLong(inst.getRawInstruction());
		}
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("BPF Program with ").append(length).append(" instructions:\n");

		for (int i = 0; i < length; i++) {
			sb.append(String.format("%4d: %s%n", i, instructions[i].toString()));
		}

		if (!validated) {
			sb.append("Program not validated\n");
		} else if (validationError != null) {
			sb.append("Validation failed: ").append(validationError).append('\n');
		} else {
			sb.append("Program validated successfully\n");
		}

		return sb.toString();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null || getClass() != obj.getClass())
			return false;

		BpfProgram other = (BpfProgram) obj;
		return length == other.length &&
				Arrays.equals(instructions, other.instructions);
	}

	@Override
	public int hashCode() {
		return 31 * length + Arrays.hashCode(instructions);
	}

	/**
	 * @see java.lang.Iterable#iterator()
	 */
	@Override
	public Iterator<BpfInstruction> iterator() {
		return new Iterator<BpfInstruction>() {
			int i = 0;

			@Override
			public BpfInstruction next() {
				return getInstruction(i++);
			}

			@Override
			public boolean hasNext() {
				return i < getLength();
			}
		};
	}
}