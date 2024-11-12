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
package com.slytechs.jnet.jnetruntime.bpf.vm.core;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * Represents a compiled BPF (Berkeley Packet Filter) program composed of a
 * sequence of BPF instructions. This class encapsulates the binary
 * representation of the program, maintains metadata such as instruction count
 * and validation status, and provides methods for program manipulation and
 * validation.
 * <p>
 * A {@code BpfProgram} is immutable once created, ensuring thread-safety and
 * consistency across different usages within the system. It offers various
 * factory methods to create instances from different sources, such as raw
 * instruction arrays or byte buffers.
 * </p>
 * <p>
 * Additionally, the class implements {@link Iterable}, allowing iteration over
 * individual {@link BpfInstruction} instances within the program.
 * </p>
 * 
 * @author
 * @version 1.0.0
 */
public class BpfProgram implements Iterable<BpfInstruction> {

	/** Maximum allowed instructions in a single BPF program */
	private static final int MAX_INSTRUCTIONS = 4096;

	/**
	 * Creates a new {@code BpfProgram} from a {@link ByteBuffer} containing raw
	 * instruction data.
	 * <p>
	 * The buffer must contain a complete set of 64-bit instructions. Each
	 * instruction is read sequentially from the buffer and encapsulated within a
	 * {@link BpfInstruction} object.
	 * </p>
	 * 
	 * @param buffer {@code ByteBuffer} containing raw 64-bit instructions
	 * @return A new {@code BpfProgram} instance containing the instructions from
	 *         the buffer
	 * @throws IllegalArgumentException if the buffer does not contain a complete
	 *                                  set of 64-bit instructions
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
	 * Creates a new {@code BpfProgram} from an array of raw 64-bit instruction
	 * values.
	 * <p>
	 * Each raw instruction is encapsulated within a {@link BpfInstruction} object.
	 * </p>
	 * 
	 * @param rawInstructions Array of raw 64-bit instruction values
	 * @return A new {@code BpfProgram} instance containing the provided
	 *         instructions
	 * @throws IllegalArgumentException if the number of instructions exceeds
	 *                                  {@link #MAX_INSTRUCTIONS}
	 */
	public static BpfProgram fromRawInstructions(long[] rawInstructions) {
		BpfInstruction[] instructions = new BpfInstruction[rawInstructions.length];
		for (int i = 0; i < rawInstructions.length; i++) {
			instructions[i] = new BpfInstruction(rawInstructions[i]);
		}

		return new BpfProgram(instructions);
	}

	/** Array of instructions comprising the BPF program */
	private final BpfInstruction[] instructions;

	/** Array of instructions comprising the BPF program as raw instructions */
	private final long[] rawInstructions;

	/** Total number of instructions in the BPF program */
	private final int length;

	/** Indicates whether the program has been validated */
	private boolean validated;

	/** Error message detailing validation issues, if any */
	private String validationError;

	/**
	 * Constructs a new {@code BpfProgram} from an array of {@link BpfInstruction}.
	 * <p>
	 * The provided instruction array is cloned to ensure immutability of the
	 * program.
	 * </p>
	 * 
	 * @param instructions Array of {@code BpfInstruction} objects representing the
	 *                     BPF program
	 * @throws IllegalArgumentException if the number of instructions exceeds
	 *                                  {@link #MAX_INSTRUCTIONS}
	 */
	public BpfProgram(BpfInstruction[] instructions) {
		if (instructions.length > MAX_INSTRUCTIONS) {
			throw new IllegalArgumentException(
					"Program exceeds maximum instruction limit of " + MAX_INSTRUCTIONS);
		}
		this.instructions = instructions.clone();
		this.length = instructions.length;
		this.validated = false;
		this.rawInstructions = new long[length];

		writeToArray(rawInstructions);
	}

	/**
	 * Determines whether this {@code BpfProgram} is equal to another object.
	 * <p>
	 * Two {@code BpfProgram} instances are considered equal if they contain the
	 * same number of instructions and all corresponding instructions are identical.
	 * </p>
	 * 
	 * @param obj The object to compare with
	 * @return {@code true} if the programs are equal; {@code false} otherwise
	 */
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

	/**
	 * Retrieves the {@link BpfInstruction} at the specified program counter
	 * (instruction index).
	 * 
	 * @param pc Program counter indicating the index of the desired instruction
	 * @return The {@code BpfInstruction} at the specified index
	 * @throws IndexOutOfBoundsException if the program counter is out of valid
	 *                                   range
	 */
	public BpfInstruction getInstruction(int pc) {
		if (pc < 0 || pc >= length) {
			throw new IndexOutOfBoundsException("Invalid program counter: " + pc);
		}

		return instructions[pc];
	}

	/**
	 * Returns the total number of instructions in the BPF program.
	 * 
	 * @return The number of instructions in the program
	 */
	public int getLength() {
		return length;
	}

	/**
	 * Retrieves the validation error message, if any.
	 * 
	 * @return The validation error message, or {@code null} if the program is valid
	 *         or not yet validated
	 */
	public String getValidationError() {
		return validationError;
	}

	/**
	 * Returns a hash code value for the {@code BpfProgram}.
	 * <p>
	 * The hash code is computed based on the number of instructions and the
	 * instructions themselves.
	 * </p>
	 * 
	 * @return A hash code value for this program
	 */
	@Override
	public int hashCode() {
		return 31 * length + Arrays.hashCode(instructions);
	}

	/**
	 * Indicates whether the BPF program has been validated.
	 * 
	 * @return {@code true} if the program has been validated; {@code false}
	 *         otherwise
	 */
	public boolean isValidated() {
		return validated;
	}

	/**
	 * Returns an iterator over the {@link BpfInstruction} elements in this program.
	 * <p>
	 * The iterator traverses the instructions in order, starting from the first
	 * instruction.
	 * </p>
	 * 
	 * @return An {@code Iterator} over the program's instructions
	 */
	@Override
	public Iterator<BpfInstruction> iterator() {
		return new Iterator<BpfInstruction>() {
			int i = 0;

			@Override
			public boolean hasNext() {
				return i < getLength();
			}

			@Override
			public BpfInstruction next() {
				return getInstruction(i++);
			}
		};
	}

	/**
	 * Sets the validation status and associated error message for the BPF program.
	 * <p>
	 * This method is typically called after performing a validation check on the
	 * program.
	 * </p>
	 * 
	 * @param validated {@code true} if the program passed validation; {@code false}
	 *                  otherwise
	 * @param error     The error message detailing validation failures, or
	 *                  {@code null} if validated successfully
	 */
	public void setValidationStatus(boolean validated, String error) {
		this.validated = validated;
		this.validationError = error;
	}

	/**
	 * Returns a stream of the {@link BpfInstruction} elements in this program.
	 * <p>
	 * The iterator traverses the instructions in order, starting from the first
	 * instruction.
	 * </p>
	 * 
	 * @return A {@code Stream} over the program's instructions
	 */
	public Stream<BpfInstruction> stream() {
		return Stream.of(instructions);
	}

	/**
	 * Alias for {@link #toRawInstructions()}.
	 * 
	 * @return An array of raw 64-bit instruction values representing the program
	 */
	public long[] toArray() {
		return rawInstructions.clone();
	}

	/**
	 * Converts the BPF program into an array of raw 64-bit instruction values.
	 * 
	 * @return An array of raw 64-bit instruction values representing the program
	 */
	public long[] toRawInstructions() {
		return rawInstructions.clone();
	}

	/**
	 * Returns a string representation of the BPF program, including all
	 * instructions and validation status.
	 * <p>
	 * Each instruction is listed with its program counter (PC) and detailed
	 * representation. The validation status indicates whether the program has been
	 * validated, and if so, whether it passed or failed.
	 * </p>
	 * 
	 * @return A string representation of the BPF program
	 */
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

	/**
	 * Writes the BPF program's raw instructions into the provided array starting at
	 * index 0.
	 * 
	 * @param raw Array to populate with raw 64-bit instruction values
	 * @return The number of instructions written to the array
	 * @throws IllegalArgumentException       if the array is {@code null}
	 * @throws ArrayIndexOutOfBoundsException if the array does not have sufficient
	 *                                        length to hold all instructions
	 */
	public int writeToArray(long[] raw) {
		return writeToArray(raw, 0);
	}

	/**
	 * Writes the BPF program's raw instructions into the provided array starting at
	 * the specified offset.
	 * 
	 * @param raw    Array to populate with raw 64-bit instruction values
	 * @param offset The starting index within the array to begin writing
	 * @return The number of instructions written to the array
	 * @throws ArrayIndexOutOfBoundsException if the offset and instruction count
	 *                                        exceed the array's length
	 * @throws NullPointerException           if the array is {@code null}
	 */
	public int writeToArray(long[] raw, int offset) {
		Objects.checkFromIndexSize(offset, length, raw.length);

		for (int i = 0; i < length; i++) {
			raw[offset + i] = rawInstructions[i];
		}

		return length;
	}

	/**
	 * Writes the BPF program's raw instructions into the specified
	 * {@link ByteBuffer}.
	 * <p>
	 * The buffer must have sufficient remaining capacity to hold all instructions
	 * (each instruction is 8 bytes).
	 * </p>
	 * 
	 * @param buffer {@code ByteBuffer} to write the raw instructions into
	 * @return The number of instructions written to the buffer
	 * @throws IllegalArgumentException if the buffer does not have enough remaining
	 *                                  space
	 */
	public int writeToBuffer(ByteBuffer buffer) {
		if (buffer.remaining() < length * 8) {
			throw new IllegalArgumentException("Insufficient buffer space");
		}

		for (long rawInstruction : rawInstructions) {
			buffer.putLong(rawInstruction);
		}

		return length;
	}

	/**
	 * Writes the BPF program's raw instructions to a specified
	 * {@link MemorySegment} starting at the given offset.
	 * <p>
	 * This method allows the program to be loaded into native memory for execution
	 * or further processing.
	 * </p>
	 * 
	 * @param segment {@code MemorySegment} representing the target native memory
	 *                area
	 * @param offset  The starting byte offset within the memory segment to begin
	 *                writing
	 * @return The number of instructions written to memory
	 * @throws IndexOutOfBoundsException if the offset and instruction count exceed
	 *                                   the memory segment's size
	 */
	public int writeToMemory(MemorySegment segment, long offset) {
		Objects.checkFromIndexSize(offset, length, segment.byteSize());

		for (int i = 0; i < length; i++) {
			long rawInstruction = instructions[i].getRawInstruction();
			segment.set(ValueLayout.JAVA_LONG, offset + (i * 8), rawInstruction);
		}

		return length;
	}
}
