package com.slytechs.jnet.jnetpcap.bpf.vm.core;

import com.slytechs.jnet.jnetpcap.bpf.vm.instruction.BpfOpcode;

/**
 * Core instruction interpreter for the BPF virtual machine. Handles instruction
 * execution and maintains program state. This interpreter is stateless; the
 * execution context is provided with each execute call, allowing for
 * multi-threaded execution without shared state.
 */
public class BpfInterpreter {

	/** Maximum number of executed instructions before timeout */
	private static final int MAX_INSTRUCTIONS = 1024 * 1024;

	/** Program being executed */
	private BpfProgram program;

	/** Instruction counter for timeout detection */
	private int instructionCount;

	/**
	 * Executes a BPF program with the provided context.
	 *
	 * @param program Program to execute
	 * @param context Execution context
	 * @return Program result
	 * @throws BpfExecutionException if execution fails
	 */
	public long execute(BpfProgram program, BpfContext context) {
		if (!program.isValidated()) {
			throw new BpfExecutionException("Cannot execute unvalidated program");
		}

		this.program = program;
		this.instructionCount = 0;
		context.reset();

		try {
			while (!context.isTerminated()) {
				if (instructionCount++ > MAX_INSTRUCTIONS) {
					throw new BpfExecutionException("Program timeout - too many instructions executed");
				}

				executeInstruction(context);

				if (context.getProgramCounter() >= program.getLength()) {
					throw new BpfExecutionException("Program counter exceeded program length");
				}
			}

			return context.getResult();

		} catch (Exception e) {
			throw new BpfExecutionException("Execution failed: " + e.getMessage(), e);
		}
	}

	/**
	 * Executes the current instruction using the provided context.
	 *
	 * @param context Execution context
	 */
	private void executeInstruction(BpfContext context) {
		int pc = context.getProgramCounter();
		BpfInstruction inst = program.getInstruction(pc);
		BpfOpcode opcode = inst.getOpcodeEnum();

		// Advance PC by default
		context.incrementProgramCounter();

		switch (opcode) {
		// Load instructions
		case LD_IMM:
			executeLdImm(inst, context);
			break;
		case LD_ABS_W:
			executeLdAbsWord(inst, context);
			break;
		case LD_ABS_H:
			executeLdAbsHalf(inst, context);
			break;
		case LD_ABS_B:
			executeLdAbsByte(inst, context);
			break;
		case LD_IND_W:
			executeLdIndWord(inst, context);
			break;
		case LD_IND_H:
			executeLdIndHalf(inst, context);
			break;
		case LD_IND_B:
			executeLdIndByte(inst, context);
			break;
		case LDX_IMM:
			executeLdxImm(inst, context);
			break;
		case LDX_MEM:
			executeLdxMem(inst, context);
			break;
		case LD_MEM:
			executeLdMem(inst, context);
			break;
		case LDX_MSH:
			executeLdxMsh(inst, context);
			break;
		case LD_MSH:
			executeLdMsh(inst, context);
			break;
		case LDX_LEN:
			executeLdxLen(context);
			break;
		case LD_LEN:
			executeLdLen(context);
			break;

		// Store instructions
		case ST:
			executeSt(inst, context);
			break;
		case STX:
			executeStx(inst, context);
			break;

		// ALU instructions (immediate)
		case ADD_K:
			executeAluK(inst, context, AluOp.ADD);
			break;
		case SUB_K:
			executeAluK(inst, context, AluOp.SUB);
			break;
		case MUL_K:
			executeAluK(inst, context, AluOp.MUL);
			break;
		case DIV_K:
			executeAluK(inst, context, AluOp.DIV);
			break;
		case OR_K:
			executeAluK(inst, context, AluOp.OR);
			break;
		case AND_K:
			executeAluK(inst, context, AluOp.AND);
			break;
		case LSH_K:
			executeAluK(inst, context, AluOp.LSH);
			break;
		case RSH_K:
			executeAluK(inst, context, AluOp.RSH);
			break;
		case MOD_K:
			executeAluK(inst, context, AluOp.MOD);
			break;
		case XOR_K:
			executeAluK(inst, context, AluOp.XOR);
			break;
		case NEG:
			executeNeg(context);
			break;

		// ALU instructions with X register
		case ADD_X:
			executeAluX(context, AluOp.ADD);
			break;
		case SUB_X:
			executeAluX(context, AluOp.SUB);
			break;
		case MUL_X:
			executeAluX(context, AluOp.MUL);
			break;
		case DIV_X:
			executeAluX(context, AluOp.DIV);
			break;
		case OR_X:
			executeAluX(context, AluOp.OR);
			break;
		case AND_X:
			executeAluX(context, AluOp.AND);
			break;
		case LSH_X:
			executeAluX(context, AluOp.LSH);
			break;
		case RSH_X:
			executeAluX(context, AluOp.RSH);
			break;
		case MOD_X:
			executeAluX(context, AluOp.MOD);
			break;
		case XOR_X:
			executeAluX(context, AluOp.XOR);
			break;

		// Jump instructions
		case JMP_JA:
			executeJumpAlways(inst, context);
			break;
		case JMP_JEQ_K:
			executeJumpEqualImmediate(inst, context);
			break;
		case JMP_JGT_K:
			executeJumpGreaterImmediate(inst, context);
			break;
		case JMP_JGE_K:
			executeJumpGreaterEqualImmediate(inst, context);
			break;
		case JMP_JSET_K:
			executeJumpSetImmediate(inst, context);
			break;
		case JMP_JEQ_X:
			executeJumpEqualX(inst, context);
			break;
		case JMP_JGT_X:
			executeJumpGreaterX(inst, context);
			break;
		case JMP_JGE_X:
			executeJumpGreaterEqualX(inst, context);
			break;
		case JMP_JSET_X:
			executeJumpSetX(inst, context);
			break;

		// Return instructions
		case RET_K:
			executeRetK(inst, context);
			break;
		case RET_A:
			executeRetA(context);
			break;

		// Misc instructions
		case TAX:
			executeTax(context);
			break;
		case TXA:
			executeTxa(context);
			break;

		// Extended instructions
		default:
			if (opcode.isExtension()) {
				executeExtended(inst, context);
			} else {
				throw new BpfExecutionException("Unknown opcode: " + opcode);
			}
		}
	}

	/**
	 * ALU operation types
	 */
	private enum AluOp {
		ADD, SUB, MUL, DIV, AND, OR, LSH, RSH, MOD, XOR
	}

	// Instruction implementations

	// Load instructions

	private void executeLdImm(BpfInstruction inst, BpfContext context) {
		context.getRegisters().setA(inst.getImmediate() & 0xFFFFFFFFL);
	}

	private void executeLdAbsByte(BpfInstruction inst, BpfContext context) {
		int offset = inst.getImmediate();
		try {
			long value = context.getMemory().readByte(offset) & 0xFFL;
			context.getRegisters().setA(value);
		} catch (BpfMemory.BpfMemoryAccessException e) {
			context.getRegisters().setA(0);
			context.getRegisters().setError(BpfRegisters.ERROR_TRUNCATED);
		}
	}

	private void executeLdAbsHalf(BpfInstruction inst, BpfContext context) {
		int offset = inst.getImmediate();
		try {
			long value = context.getMemory().readShort(offset) & 0xFFFFL;
			context.getRegisters().setA(value);
		} catch (BpfMemory.BpfMemoryAccessException e) {
			context.getRegisters().setA(0);
			context.getRegisters().setError(BpfRegisters.ERROR_TRUNCATED);
		}
	}

	private void executeLdAbsWord(BpfInstruction inst, BpfContext context) {
		int offset = inst.getImmediate();
		try {
			long value = context.getMemory().readInt(offset) & 0xFFFFFFFFL;
			context.getRegisters().setA(value);
		} catch (BpfMemory.BpfMemoryAccessException e) {
			context.getRegisters().setA(0);
			context.getRegisters().setError(BpfRegisters.ERROR_TRUNCATED);
		}
	}

	private void executeLdIndByte(BpfInstruction inst, BpfContext context) {
		int offset = (int) context.getRegisters().getX() + inst.getImmediate();
		try {
			long value = context.getMemory().readByte(offset) & 0xFFL;
			context.getRegisters().setA(value);
		} catch (BpfMemory.BpfMemoryAccessException e) {
			context.getRegisters().setA(0);
			context.getRegisters().setError(BpfRegisters.ERROR_TRUNCATED);
		}
	}

	private void executeLdIndHalf(BpfInstruction inst, BpfContext context) {
		int offset = (int) context.getRegisters().getX() + inst.getImmediate();
		try {
			long value = context.getMemory().readShort(offset) & 0xFFFFL;
			context.getRegisters().setA(value);
		} catch (BpfMemory.BpfMemoryAccessException e) {
			context.getRegisters().setA(0);
			context.getRegisters().setError(BpfRegisters.ERROR_TRUNCATED);
		}
	}

	private void executeLdIndWord(BpfInstruction inst, BpfContext context) {
		int offset = (int) context.getRegisters().getX() + inst.getImmediate();
		try {
			long value = context.getMemory().readInt(offset) & 0xFFFFFFFFL;
			context.getRegisters().setA(value);
		} catch (BpfMemory.BpfMemoryAccessException e) {
			context.getRegisters().setA(0);
			context.getRegisters().setError(BpfRegisters.ERROR_TRUNCATED);
		}
	}

	private void executeLdLen(BpfContext context) {
		long len = context.getMemory().getPacketLength() & 0xFFFFFFFFL;
		context.getRegisters().setA(len);
	}

	private void executeLdMem(BpfInstruction inst, BpfContext context) {
		int index = inst.getImmediate();
		long value = context.getRegisters().get(index);
		context.getRegisters().setA(value);
	}

	private void executeLdMsh(BpfInstruction inst, BpfContext context) {
		int offset = inst.getImmediate();
		try {
			int value = context.getMemory().readByte(offset) & 0xFF;
			value = (value & 0x0F) << 2;
			context.getRegisters().setA(value & 0xFFFFFFFFL);
		} catch (BpfMemory.BpfMemoryAccessException e) {
			context.getRegisters().setA(0);
			context.getRegisters().setError(BpfRegisters.ERROR_TRUNCATED);
		}
	}

	private void executeLdxImm(BpfInstruction inst, BpfContext context) {
		context.getRegisters().setX(inst.getImmediate() & 0xFFFFFFFFL);
	}

	private void executeLdxLen(BpfContext context) {
		long len = context.getMemory().getPacketLength() & 0xFFFFFFFFL;
		context.getRegisters().setX(len);
	}

	private void executeLdxMem(BpfInstruction inst, BpfContext context) {
		int index = inst.getImmediate();
		long value = context.getRegisters().get(index);
		context.getRegisters().setX(value);
	}

	private void executeLdxMsh(BpfInstruction inst, BpfContext context) {
		int offset = inst.getImmediate();
		try {
			int value = context.getMemory().readByte(offset) & 0xFF;
			value = (value & 0x0F) << 2;
			context.getRegisters().setX(value & 0xFFFFFFFFL);
		} catch (BpfMemory.BpfMemoryAccessException e) {
			context.getRegisters().setX(0);
			context.getRegisters().setError(BpfRegisters.ERROR_TRUNCATED);
		}
	}

	// Store instructions
	private void executeSt(BpfInstruction inst, BpfContext context) {
		int index = inst.getImmediate();
		context.getRegisters().set(index, context.getRegisters().getA());
	}

	private void executeStx(BpfInstruction inst, BpfContext context) {
		int index = inst.getImmediate();
		context.getRegisters().set(index, context.getRegisters().getX());
	}

	// ALU instructions (immediate)
	private void executeAluK(BpfInstruction inst, BpfContext context, AluOp op) {
		long a = context.getRegisters().getA();
		long k = inst.getImmediate() & 0xFFFFFFFFL;
		context.getRegisters().setA(executeAlu(a, k, op));
	}

	// ALU instructions with X register
	private void executeAluX(BpfContext context, AluOp op) {
		long a = context.getRegisters().getA();
		long x = context.getRegisters().getX();
		context.getRegisters().setA(executeAlu(a, x, op));
	}

	private long executeAlu(long a, long b, AluOp op) {
		switch (op) {
		case ADD:
			return (a + b) & 0xFFFFFFFFL;
		case SUB:
			return (a - b) & 0xFFFFFFFFL;
		case MUL:
			return (a * b) & 0xFFFFFFFFL;
		case DIV:
			return b != 0 ? (a / b) & 0xFFFFFFFFL : 0;
		case AND:
			return (a & b) & 0xFFFFFFFFL;
		case OR:
			return (a | b) & 0xFFFFFFFFL;
		case LSH:
			return (a << b) & 0xFFFFFFFFL;
		case RSH:
			return (a >>> b) & 0xFFFFFFFFL;
		case MOD:
			return b != 0 ? (a % b) & 0xFFFFFFFFL : 0;
		case XOR:
			return (a ^ b) & 0xFFFFFFFFL;
		default:
			throw new BpfExecutionException("Unknown ALU operation");
		}
	}

	private void executeNeg(BpfContext context) {
		long a = context.getRegisters().getA();
		context.getRegisters().setA((-a) & 0xFFFFFFFFL);
	}

	// Jump instructions

	private void executeJumpAlways(BpfInstruction inst, BpfContext context) {
		int offset = inst.getImmediate();
		context.setProgramCounter(context.getProgramCounter() + offset);
	}

	private void executeJumpEqualImmediate(BpfInstruction inst, BpfContext context) {
		long a = context.getRegisters().getA();
		long k = inst.getImmediate() & 0xFFFFFFFFL;
		int jt = inst.getDst();
		int jf = inst.getSrc();

		if (a == k) {
			context.setProgramCounter(context.getProgramCounter() + jt - 1);
		} else {
			context.setProgramCounter(context.getProgramCounter() + jf - 1);
		}
	}

	private void executeJumpGreaterImmediate(BpfInstruction inst, BpfContext context) {
		long a = context.getRegisters().getA();
		long k = inst.getImmediate() & 0xFFFFFFFFL;
		int jt = inst.getDst();
		int jf = inst.getSrc();

		if (a > k) {
			context.setProgramCounter(context.getProgramCounter() + jt - 1);
		} else {
			context.setProgramCounter(context.getProgramCounter() + jf - 1);
		}
	}

	private void executeJumpGreaterEqualImmediate(BpfInstruction inst, BpfContext context) {
		long a = context.getRegisters().getA();
		long k = inst.getImmediate() & 0xFFFFFFFFL;
		int jt = inst.getDst();
		int jf = inst.getSrc();

		if (a >= k) {
			context.setProgramCounter(context.getProgramCounter() + jt - 1);
		} else {
			context.setProgramCounter(context.getProgramCounter() + jf - 1);
		}
	}

	private void executeJumpSetImmediate(BpfInstruction inst, BpfContext context) {
		long a = context.getRegisters().getA();
		long k = inst.getImmediate() & 0xFFFFFFFFL;
		int jt = inst.getDst();
		int jf = inst.getSrc();

		if ((a & k) != 0) {
			context.setProgramCounter(context.getProgramCounter() + jt - 1);
		} else {
			context.setProgramCounter(context.getProgramCounter() + jf - 1);
		}
	}

	private void executeJumpEqualX(BpfInstruction inst, BpfContext context) {
		long a = context.getRegisters().getA();
		long x = context.getRegisters().getX();
		int jt = inst.getDst();
		int jf = inst.getSrc();

		if (a == x) {
			context.setProgramCounter(context.getProgramCounter() + jt - 1);
		} else {
			context.setProgramCounter(context.getProgramCounter() + jf - 1);
		}
	}

	private void executeJumpGreaterX(BpfInstruction inst, BpfContext context) {
		long a = context.getRegisters().getA();
		long x = context.getRegisters().getX();
		int jt = inst.getDst();
		int jf = inst.getSrc();

		if (a > x) {
			context.setProgramCounter(context.getProgramCounter() + jt - 1);
		} else {
			context.setProgramCounter(context.getProgramCounter() + jf - 1);
		}
	}

	private void executeJumpGreaterEqualX(BpfInstruction inst, BpfContext context) {
		long a = context.getRegisters().getA();
		long x = context.getRegisters().getX();
		int jt = inst.getDst();
		int jf = inst.getSrc();

		if (a >= x) {
			context.setProgramCounter(context.getProgramCounter() + jt - 1);
		} else {
			context.setProgramCounter(context.getProgramCounter() + jf - 1);
		}
	}

	private void executeJumpSetX(BpfInstruction inst, BpfContext context) {
		long a = context.getRegisters().getA();
		long x = context.getRegisters().getX();
		int jt = inst.getDst();
		int jf = inst.getSrc();

		if ((a & x) != 0) {
			context.setProgramCounter(context.getProgramCounter() + jt - 1);
		} else {
			context.setProgramCounter(context.getProgramCounter() + jf - 1);
		}
	}

	// Return instructions
	private void executeRetK(BpfInstruction inst, BpfContext context) {
		context.setResult(inst.getImmediate() & 0xFFFFFFFFL);
	}

	private void executeRetA(BpfContext context) {
		context.setResult(context.getRegisters().getA());
	}

	// Misc instructions
	private void executeTax(BpfContext context) {
		context.getRegisters().setX(context.getRegisters().getA());
	}

	private void executeTxa(BpfContext context) {
		context.getRegisters().setA(context.getRegisters().getX());
	}

	private void executeExtended(BpfInstruction inst, BpfContext context) {
		BpfOpcode opcode = inst.getOpcodeEnum();

		switch (opcode) {
		case CHK_CRC:
			executeCheckCrc(inst, context);
			break;

		case CHK_L3_CSUM:
			executeCheckL3Checksum(inst, context);
			break;

//		case CHK_L4_CSUM:
//			executeCheckL4Checksum(inst, context);
//			break;
//
//		case CHK_TRUNC:
//			executeCheckTruncated(inst, context);
//			break;
//
//		case CHK_FRAME_LEN:
//			executeCheckFrameLength(inst, context);
//			break;
//
//		case CHK_PROTO_LOC:
//			executeCheckProtoLocation(inst, context);
//			break;

		default:
			throw new BpfExecutionException("Unknown extended instruction: " + opcode);
		}
	}
	
	private void executeCheckCrc(BpfInstruction inst, BpfContext context) {
	    int offset = inst.getImmediate();
	    int length = inst.getSrc();
	    // Implement CRC check logic here
//	    boolean crcValid = performCrcCheck(context.getMemory(), offset, length);
//	    if (!crcValid) {
//	        context.terminate(); // Example action on CRC failure
//	    }
	}

	private void executeCheckL3Checksum(BpfInstruction inst, BpfContext context) {
	    // Implement Layer 3 checksum verification
//	    boolean l3CsumValid = verifyL3Checksum(context.getMemory());
//	    if (!l3CsumValid) {
//	        context.terminate(); // Example action on checksum failure
//	    }
	}

	// Implement other methods similarly...


	/**
	 * Exception thrown for BPF execution errors.
	 */
	public static class BpfExecutionException extends RuntimeException {
		private static final long serialVersionUID = 1L;

		public BpfExecutionException(String message) {
			super(message);
		}

		public BpfExecutionException(String message, Throwable cause) {
			super(message, cause);
		}
	}
}
