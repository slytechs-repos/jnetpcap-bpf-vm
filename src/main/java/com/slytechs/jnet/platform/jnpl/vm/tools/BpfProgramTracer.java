package com.slytechs.jnet.platform.jnpl.vm.tools;

import java.util.ArrayList;
import java.util.List;

import com.slytechs.jnet.platform.jnpl.vm.core.BpfContext;
import com.slytechs.jnet.platform.jnpl.vm.core.BpfInstruction;
import com.slytechs.jnet.platform.jnpl.vm.core.BpfVirtualMachine;

/**
 * Traces BPF program execution for debugging and analysis.
 */
public class BpfProgramTracer {
    
    private final List<TraceEntry> trace = new ArrayList<>();
    private final BpfVirtualMachine vm;
    private boolean enabled = false;
    
    /**
     * Creates a new program tracer.
     * 
     * @param vm Virtual machine to trace
     */
    public BpfProgramTracer(BpfVirtualMachine vm) {
        this.vm = vm;
    }
    
    /**
     * Enables or disables tracing.
     * 
     * @param enabled true to enable tracing
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    /**
     * Records an instruction execution.
     * 
     * @param pc Program counter
     * @param inst Executed instruction
     * @param context Execution context
     */
    public void recordInstruction(int pc, BpfInstruction inst, BpfContext context) {
        if (!enabled) return;
        
        trace.add(new TraceEntry(
            pc,
            inst,
            context.getRegisters().getA(),
            context.getRegisters().getX(),
            context.isTerminated()
        ));
    }
    
    /**
     * Gets the execution trace.
     * 
     * @return List of trace entries
     */
    public List<TraceEntry> getTrace() {
        return new ArrayList<>(trace);
    }
    
    /**
     * Clears the trace.
     */
    public void clear() {
        trace.clear();
    }
    
    /**
     * Gets a formatted trace dump.
     * 
     * @return Formatted trace
     */
    public String getTraceDump() {
        StringBuilder sb = new StringBuilder();
        sb.append("BPF Program Execution Trace\n");
        sb.append("-------------------------\n");
        
        for (TraceEntry entry : trace) {
            sb.append(String.format(
                "%04d: %-20s  A=0x%08x  X=0x%08x  %s%n",
                entry.pc,
                entry.instruction.toString(),
                entry.accumulator,
                entry.index,
                entry.terminated ? "[Terminated]" : ""
            ));
        }
        
        return sb.toString();
    }
    
    /**
     * Trace entry recording a single instruction execution.
     */
    public static class TraceEntry {
        private final int pc;
        private final BpfInstruction instruction;
        private final long accumulator;
        private final long index;
        private final boolean terminated;
        
        TraceEntry(int pc, BpfInstruction instruction, long accumulator, 
                  long index, boolean terminated) {
            this.pc = pc;
            this.instruction = instruction;
            this.accumulator = accumulator;
            this.index = index;
            this.terminated = terminated;
        }
        
        public int getPc() { return pc; }
        public BpfInstruction getInstruction() { return instruction; }
        public long getAccumulator() { return accumulator; }
        public long getIndex() { return index; }
        public boolean isTerminated() { return terminated; }
    }
}