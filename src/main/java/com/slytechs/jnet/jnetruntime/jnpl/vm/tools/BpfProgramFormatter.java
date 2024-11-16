package com.slytechs.jnet.jnetruntime.jnpl.vm.tools;

import com.slytechs.jnet.jnetruntime.jnpl.vm.core.BpfInstruction;
import com.slytechs.jnet.jnetruntime.jnpl.vm.core.BpfProgram;
import com.slytechs.jnet.jnetruntime.jnpl.vm.instruction.BpfOpcode;

/**
 * Formats BPF programs in various output styles.
 */
public class BpfProgramFormatter {

	/**
	 * Output format styles.
	 */
	public enum OutputStyle {
		TCPDUMP, // tcpdump-style output
		C_CODE, // C code representation
		ASSEMBLY, // Assembly-style representation
		HEX // Hexadecimal format
	}

	private final BpfProgram program;

	/**
	 * Creates a new program formatter.
	 * 
	 * @param program Program to format
	 */
	public BpfProgramFormatter(BpfProgram program) {
		this.program = program;
	}

	/**
	 * Formats the program in specified style.
	 * 
	 * @param style Output style
	 * @return Formatted program
	 */
	public String format(OutputStyle style) {
		switch (style) {
		case TCPDUMP:
			return formatTcpdump();
		case C_CODE:
			return formatCCode();
		case ASSEMBLY:
			return formatAssembly();
		case HEX:
			return formatHex();
		default:
			throw new IllegalArgumentException("Unknown output style");
		}
	}

	/**
	 * Formats program in tcpdump style.
	 */
	private String formatTcpdump() {
		StringBuilder sb = new StringBuilder();

		for (int i = 0; i < program.getLength(); i++) {
			BpfInstruction inst = program.getInstruction(i);
			sb.append(String.format("(%03d) ", i));

			BpfOpcode opcode = inst.getOpcodeEnum();
			if (opcode.isJump() && opcode != BpfOpcode.JMP_JA) {
				sb.append(String.format("%-8s #0x%x\tjt %d\tjf %d\n",
						opcode.getMnemonic(),
						inst.getImmediate(),
						inst.getDst(),
						inst.getSrc()));
			} else {
				sb.append(String.format("%-8s 0x%x\n",
						opcode.getMnemonic(),
						inst.getImmediate()));
			}
		}

		return sb.toString();
	}

	/**
	 * Formats program as C code.
	 */
	private String formatCCode() {
		StringBuilder sb = new StringBuilder();
		sb.append("static struct bpf_insn filter[] = {\n");

		for (int i = 0; i < program.getLength(); i++) {
			BpfInstruction inst = program.getInstruction(i);
			sb.append(String.format("    { 0x%02x, %d, %d, 0x%08x },\n",
					inst.getOpcode(),
					inst.getDst(),
					inst.getSrc(),
					inst.getImmediate()));
		}

		sb.append("};\n");
		return sb.toString();
	}

	/**
	 * Formats program in assembly style.
	 */
	private String formatAssembly() {
		StringBuilder sb = new StringBuilder();

		for (int i = 0; i < program.getLength(); i++) {
			BpfInstruction inst = program.getInstruction(i);
			BpfOpcode opcode = inst.getOpcodeEnum();

			sb.append(String.format("%04d:\t", i));

			if (opcode.isJump()) {
				if (opcode == BpfOpcode.JMP_JA) {
					sb.append(String.format("%s\t.L%d\n",
							opcode.getMnemonic(),
							i + 1 + inst.getImmediate()));
				} else {
					sb.append(String.format("%s\t0x%x, .L%d, .L%d\n",
							opcode.getMnemonic(),
							inst.getImmediate(),
							inst.getDst(),
							inst.getSrc()));
				}
			} else {
				sb.append(String.format("%s\t0x%x\n",
						opcode.getMnemonic(),
						inst.getImmediate()));
			}
		}

		return sb.toString();
	}

	/**
	 * Formats program in hexadecimal.
	 */
	private String formatHex() {
		StringBuilder sb = new StringBuilder();

		for (int i = 0; i < program.getLength(); i++) {
			BpfInstruction inst = program.getInstruction(i);
			sb.append(String.format("0x%016x\n", inst.getRawInstruction()));
		}

		return sb.toString();
	}
}