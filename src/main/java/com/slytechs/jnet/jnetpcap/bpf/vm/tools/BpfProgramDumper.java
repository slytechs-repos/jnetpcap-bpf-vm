package com.slytechs.jnet.jnetpcap.bpf.vm.tools;

import com.slytechs.jnet.jnetpcap.bpf.vm.core.BpfInstruction;
import com.slytechs.jnet.jnetpcap.bpf.vm.core.BpfProgram;
import com.slytechs.jnet.jnetpcap.bpf.vm.instruction.BpfOpcode;

public class BpfProgramDumper {

	/**
	 * Dumps the BPF program into a readable string format.
	 *
	 * @param program The BPF program to dump
	 * @return A string representation of the BPF program
	 */
	public static String dump(BpfProgram program) {
		StringBuilder sb = new StringBuilder();
		int lineNum = 0;
		for (BpfInstruction inst : program) {
			sb.append(String.format("(%03d) %s\n", lineNum++, formatInstruction(inst)));
		}
		return sb.toString();
	}

	/**
	 * Formats a single BPF instruction into a readable string.
	 *
	 * @param inst The instruction to format
	 * @return A string representation of the instruction
	 */
	private static String formatInstruction(BpfInstruction inst) {
		StringBuilder sb = new StringBuilder();
		BpfOpcode opcode = inst.getOpcodeEnum();

		switch (opcode.getFormat()) {
		case MEMORY_ABS:
			sb.append(String.format("%s [%d]", opcode.getMnemonic(), inst.getImmediate()));
			break;

		case MEMORY_IND:
			sb.append(String.format("%s [x + %d]", opcode.getMnemonic(), inst.getImmediate()));
			break;

		case MEMORY_REG:
			sb.append(String.format("%s M[%d]", opcode.getMnemonic(), inst.getDst()));
			break;

		case IMMEDIATE:
			sb.append(String.format("%s #%d", opcode.getMnemonic(), inst.getImmediate()));
			break;

		case JUMP_UNCOND:
			sb.append(String.format("%s +%d", opcode.getMnemonic(), inst.getImmediate()));
			break;

		case JUMP_COND:
			sb.append(String.format("%s #%d jt %d jf %d",
					opcode.getMnemonic(), Integer.toUnsignedLong(inst.getImmediate()), inst.getDst(), inst.getSrc()));
			break;

		case REG_ONLY:
			sb.append(opcode.getMnemonic());
			break;

		case EXTENDED:
			formatExtended(sb, inst);
			break;

		default:
			sb.append(opcode.getMnemonic());
			break;
		}

		return sb.toString();
	}

	/**
	 * Formats extended instructions.
	 *
	 * @param sb   The StringBuilder to append to
	 * @param inst The instruction to format
	 */
	private static void formatExtended(StringBuilder sb, BpfInstruction inst) {
		BpfOpcode opcode = inst.getOpcodeEnum();
		switch (opcode) {
		case CHK_CRC:
			sb.append(String.format("chk_crc offset=%d len=%d",
					inst.getImmediate(), inst.getSrc()));
			break;

		case CHK_L3_CSUM:
			sb.append("chk_l3_csum");
			break;

		case CHK_L4_CSUM:
			sb.append("chk_l4_csum");
			break;

		case CHK_TRUNC:
			sb.append("chk_trunc");
			break;

		case CHK_FRAME_LEN:
			sb.append(String.format("chk_frame_len >=%d", inst.getImmediate()));
			break;

		case CHK_PROTO_LOC:
			sb.append(String.format("chk_proto_loc layer=%d offset=%d",
					inst.getDst(), inst.getImmediate()));
			break;

		case LDX_MEM_IND:
			sb.append(String.format("ldx M[%d]", inst.getImmediate()));
			break;

		default:
			sb.append(String.format("extended op=0x%x", opcode.getOpcode()));
		}
	}
}
