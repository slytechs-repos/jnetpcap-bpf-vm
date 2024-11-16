package com.slytechs.jnet.jnetruntime.jnpl.vm.tools;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

import com.slytechs.jnet.jnetruntime.jnpl.vm.core.BpfInstruction;
import com.slytechs.jnet.jnetruntime.jnpl.vm.core.BpfProgram;
import com.slytechs.jnet.jnetruntime.jnpl.vm.instruction.BpfOpcode;

/**
 * Analyzes BPF programs for structure, optimization opportunities, and
 * potential issues.
 */
public class BpfProgramAnalyzer {

	private final BpfProgram program;
	private final Set<Integer> jumpTargets = new HashSet<>();
	private final Set<Integer> deadCode = new HashSet<>();
	private final Map<Integer, Set<Integer>> controlFlow = new HashMap<>();

	/**
	 * Creates a new program analyzer.
	 * 
	 * @param program Program to analyze
	 */
	public BpfProgramAnalyzer(BpfProgram program) {
		this.program = program;
		analyze();
	}

	/**
	 * Performs program analysis.
	 */
	private void analyze() {
		findJumpTargets();
		buildControlFlow();
		findDeadCode();
	}

	/**
	 * Locates all jump targets in the program.
	 */
	private void findJumpTargets() {
		for (int i = 0; i < program.getLength(); i++) {
			BpfInstruction inst = program.getInstruction(i);
			BpfOpcode opcode = inst.getOpcodeEnum();

			if (opcode.isJump()) {
				if (opcode == BpfOpcode.JMP_JA) {
					// Unconditional jump
					jumpTargets.add(i + 1 + inst.getImmediate());
				} else {
					// Conditional jump
					jumpTargets.add(inst.getDst()); // true target
					jumpTargets.add(inst.getSrc()); // false target
				}
			}
		}
	}

	/**
	 * Builds program control flow graph.
	 */
	private void buildControlFlow() {
		for (int i = 0; i < program.getLength(); i++) {
			BpfInstruction inst = program.getInstruction(i);
			BpfOpcode opcode = inst.getOpcodeEnum();

			Set<Integer> targets = new HashSet<>();
			controlFlow.put(i, targets);

			if (opcode.isJump()) {
				if (opcode == BpfOpcode.JMP_JA) {
					targets.add(i + 1 + inst.getImmediate());
				} else {
					targets.add(inst.getDst()); // true target
					targets.add(inst.getSrc()); // false target
				}
			} else if (!opcode.isReturn()) {
				targets.add(i + 1); // fall through
			}
		}
	}

	/**
	 * Identifies unreachable code.
	 */
	private void findDeadCode() {
		Set<Integer> reachable = new HashSet<>();
		Queue<Integer> workList = new LinkedList<>();

		// Start from entry point
		workList.add(0);
		reachable.add(0);

		// Perform reachability analysis
		while (!workList.isEmpty()) {
			int current = workList.poll();
			Set<Integer> targets = controlFlow.get(current);

			if (targets != null) {
				for (int target : targets) {
					if (reachable.add(target)) {
						workList.add(target);
					}
				}
			}
		}

		// Find dead code
		for (int i = 0; i < program.getLength(); i++) {
			if (!reachable.contains(i)) {
				deadCode.add(i);
			}
		}
	}

	/**
	 * Gets program analysis report.
	 * 
	 * @return Analysis report
	 */
	public AnalysisReport getReport() {
		return new AnalysisReport(
				program.getLength(),
				jumpTargets,
				deadCode,
				findOptimizationOpportunities());
	}

	/**
	 * Identifies potential optimizations.
	 * 
	 * @return List of optimization suggestions
	 */
	private List<String> findOptimizationOpportunities() {
		List<String> opportunities = new ArrayList<>();

		// Check for redundant jumps
		for (int i = 0; i < program.getLength(); i++) {
			BpfInstruction inst = program.getInstruction(i);
			if (inst.getOpcodeEnum() == BpfOpcode.JMP_JA) {
				int target = i + 1 + inst.getImmediate();
				if (target == i + 1) {
					opportunities.add(String.format(
							"Redundant jump at instruction %d", i));
				}
			}
		}

		// Check for unreachable code
		if (!deadCode.isEmpty()) {
			opportunities.add(String.format(
					"Found %d unreachable instructions", deadCode.size()));
		}

		return opportunities;
	}

	/**
	 * Program analysis report.
	 */
	public static class AnalysisReport {
		private final int programLength;
		private final Set<Integer> jumpTargets;
		private final Set<Integer> deadCode;
		private final List<String> optimizations;

		AnalysisReport(
				int programLength,
				Set<Integer> jumpTargets,
				Set<Integer> deadCode,
				List<String> optimizations) {
			this.programLength = programLength;
			this.jumpTargets = new HashSet<>(jumpTargets);
			this.deadCode = new HashSet<>(deadCode);
			this.optimizations = new ArrayList<>(optimizations);
		}

		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder();
			sb.append("BPF Program Analysis Report\n");
			sb.append("-------------------------\n");
			sb.append(String.format("Program length: %d instructions\n", programLength));
			sb.append(String.format("Jump targets: %s\n", jumpTargets));
			sb.append(String.format("Dead code: %s\n", deadCode));
			sb.append("\nOptimization opportunities:\n");
			for (String opt : optimizations) {
				sb.append("- ").append(opt).append('\n');
			}
			return sb.toString();
		}
	}
}