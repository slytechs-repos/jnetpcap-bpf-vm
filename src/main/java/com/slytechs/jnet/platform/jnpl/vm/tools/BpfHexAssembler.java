package com.slytechs.jnet.platform.jnpl.vm.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.slytechs.jnet.platform.jnpl.vm.core.BpfInstruction;
import com.slytechs.jnet.platform.jnpl.vm.core.BpfProgram;
import com.slytechs.jnet.platform.jnpl.vm.instruction.BpfOpcode;

/**
 * Assembler for tcpdump -dd hexadecimal output format. Converts hexadecimal
 * representation of BPF instructions into executable `BpfInstruction` objects.
 */
public class BpfHexAssembler {

	// Pattern to match hex instruction format: { 0xNN, N, N, 0xNNNNNNNN }
	private static final Pattern HEX_INSTRUCTION_PATTERN = Pattern.compile(
			"\\{\\s*0x([0-9a-fA-F]+)\\s*,\\s*(\\d+)\\s*,\\s*(\\d+)\\s*,\\s*0x([0-9a-fA-F]+)\\s*\\},?");

	/**
	 * Assembles tcpdump -dd output format into a BPF program.
	 *
	 * @param hexOutput The tcpdump -dd formatted output
	 * @return Compiled BPF program
	 * @throws AssemblyException if parsing fails
	 */
	public static BpfProgram assembleHex(String hexOutput) {
		List<BpfInstruction> instructions = new ArrayList<>();

		// Split into lines and clean up
		String[] lines = hexOutput.split("\n");
		for (String line : lines) {
			line = line.trim();

			// Skip empty lines and warnings
			if (line.isEmpty() || line.startsWith("Warning:")) {
				continue;
			}

			// Remove trailing comma if present
			if (line.endsWith(",")) {
				line = line.substring(0, line.length() - 1);
			}

			try {
				BpfInstruction inst = parseHexInstruction(line);
				if (inst != null) {
					instructions.add(inst);
				}
			} catch (AssemblyException e) {
				throw new AssemblyException(
						String.format("Error at instruction %d: %s",
								instructions.size(), e.getMessage()));
			}
		}

		if (instructions.isEmpty()) {
			throw new AssemblyException("No valid instructions found in input");
		}

		return new BpfProgram(instructions.toArray(new BpfInstruction[0]));
	}

	/**
	 * Parses a single hex format instruction line.
	 */
	private static BpfInstruction parseHexInstruction(String line) {
		Matcher m = HEX_INSTRUCTION_PATTERN.matcher(line);
		if (!m.matches()) {
			throw new AssemblyException("Invalid hex instruction format: " + line);
		}

		try {
			// Parse opcode (byte)
			int opcodeValue = Integer.parseInt(m.group(1), 16) & 0xFF;
			BpfOpcode opcode = BpfOpcode.fromValue(opcodeValue);

			// Parse jt and jf (bytes)
			int jt = Integer.parseInt(m.group(2)) & 0xFF;
			int jf = Integer.parseInt(m.group(3)) & 0xFF;

			// Parse k (32-bit value)
			int k = (int) (Long.parseLong(m.group(4), 16) & 0xFFFFFFFFL);

			// Create the instruction
			return BpfInstruction.create(opcode, jt, jf, k);

		} catch (NumberFormatException e) {
			throw new AssemblyException("Failed to parse hex instruction: " + line +
					"\nError: " + e.getMessage());
		} catch (IllegalArgumentException e) {
			throw new AssemblyException("Unknown opcode in instruction: " + line +
					"\nError: " + e.getMessage());
		}
	}

	public static void main(String[] args) {
		String hexOutput = """
				{ 0x28, 0, 0, 0x0000000c },
				{ 0x15, 0, 12, 0x00000800 },
				{ 0x20, 0, 0, 0x0000001a },
				{ 0x15, 0, 10, 0xc0a80101 },
				{ 0x30, 0, 0, 0x00000017 },
				{ 0x15, 2, 0, 0x00000084 },
				{ 0x15, 1, 0, 0x00000006 },
				{ 0x15, 0, 6, 0x00000011 },
				{ 0x28, 0, 0, 0x00000014 },
				{ 0x45, 4, 0, 0x00001fff },
				{ 0xb1, 0, 0, 0x0000000e },
				{ 0x48, 0, 0, 0x00000010 },
				{ 0x15, 0, 1, 0x00000050 },
				{ 0x6, 0, 0, 0x00040000 },
				{ 0x6, 0, 0, 0x00000000 },
				""";

		try {
			BpfProgram program = BpfHexAssembler.assembleHex(hexOutput);

			// Process the program as needed
			for (BpfInstruction inst : program) {
				System.out.println(inst.getOpcodeEnum().getMnemonic());
			}

			System.out.println("-- BPF PROGRAM DUMPER -- ");

			var output = BpfProgramDumper.dump(program).toString();

			System.out.println(output);

		} catch (AssemblyException e) {
			System.err.println("Assembly failed: " + e.getMessage());
			e.printStackTrace();
		}

	}

}
