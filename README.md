Here's the updated README.md:

---

# JNetRuntime-JNPL-VM

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Java Version](https://img.shields.io/badge/java-%3E%3D%208-orange.svg)]()

A high-performance JNPL Virtual Machine implementation in Java that extends BPF OPCODES to enable advanced packet filtering and general configuration capabilities when integrated with `jNetWorks SDK` modules.

## Overview

The `jnetruntime-jnpl-vm` module provides a superset of Berkeley Packet Filter (BPF) OPCODES to allow for:

- Advanced packet filtering
- General configuration management
- Cross-syntax usage from various filter expressions

It processes standard `ASTNode` inputs as defined in the `compiler-api` module, generating intermediate representations (IR) and binary outputs for execution by the VM. This design enables seamless cross-compilation from various languages, including:

- PCAP/TCPDUMP filter syntax
- Wireshark Display Filters
- Napatech NTAPI NTPL filters
- DPDK flow patterns

## Features

### Core Capabilities

- **Extended BPF Instruction Set**:
  - Load/store operations
  - Branch and ALU operations
  - Advanced filtering instructions
  - Return and memory operations

- **Cross-Syntax Compatibility**:
  Compile filter expressions from diverse tools into a single executable binary for the JNPL VM.

- **Integration with `jNetWorks SDK`**:
  Utilize this VM alongside SDK modules to enable dynamic runtime configuration and packet filtering.

- **High Performance**:
  - Zero-copy packet processing
  - Optimized instruction dispatch
  - Minimal resource overhead

### Example Workflow

```java
// Compile filter expression to JNPL bytecode
String filter = "ip and tcp port 80";
BPFCompiler compiler = new BPFCompiler();
byte[] bytecode = compiler.compile(filter);

// Load and execute in VM
BPFProgram program = BPFProgram.load(bytecode);
boolean matches = program.execute(packet);
```

### Language Support

The JNPL VM supports cross-compilation from:

- **PCAP/TCPDUMP Filters**:
  Generate JNPL bytecode for runtime execution.

- **Wireshark Display Filters**:
  Leverage the Wireshark syntax for packet filtering in your custom applications.

- **Napatech NTAPI Filters**:
  Use NTPL filter syntax to execute hardware-compatible configurations.

- **DPDK Flow Patterns**:
  Translate DPDK-specific patterns into JNPL for software-level processing.

## Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>io.github.jnetruntime</groupId>
    <artifactId>jnetruntime-jnpl-vm</artifactId>
    <version>${latest.version}</version>
</dependency>
```

## Usage Examples

### Compiling Filters from Various Syntaxes

```java
// Compile a TCPDUMP filter
String tcpdumpFilter = "tcp and port 443";
byte[] bytecode = compiler.compile(tcpdumpFilter);

// Execute using the VM
BPFProgram program = BPFProgram.load(bytecode);
boolean matches = program.execute(packet);
```

### Custom Instruction Extension

```java
// Define a custom instruction
public class CustomJNPLInstruction implements BPFInstruction {
    @Override
    public int execute(BPFContext ctx) {
        // Custom execution logic
    }
}

// Register the instruction
JNPLVirtualMachine.registerOpcode(0xF0, new CustomJNPLInstruction());
```

### Cross-Platform Execution

Use a single JNPL VM for filters from multiple syntaxes:

```java
// Compile Napatech NTPL filter
String ntplFilter = "Match[IP.DstAddr == 192.168.0.1]";
byte[] ntplBytecode = compiler.compile(ntplFilter);

// Compile Wireshark Display Filter
String wiresharkFilter = "tcp.port == 443";
byte[] wiresharkBytecode = compiler.compile(wiresharkFilter);

// Execute in the same VM
BPFProgram program1 = BPFProgram.load(ntplBytecode);
BPFProgram program2 = BPFProgram.load(wiresharkBytecode);

boolean match1 = program1.execute(packet);
boolean match2 = program2.execute(packet);
```

## Performance

Designed for high throughput and low latency:

- **Throughput**: Processes over 1M packets/second.
- **Latency**: Sub-microsecond per packet for typical filters.
- **Efficiency**: Minimal memory overhead with zero-copy architecture.

## Building from Source

Clone the repository and build the project:

```bash
git clone https://github.com/jnetruntime/jnetruntime-jnpl-vm.git
cd jnetruntime-jnpl-vm
mvn clean install
```

## Contributing

We welcome contributions! See our [Contributing Guidelines](CONTRIBUTING.md) for details. Opportunities include:

- Adding support for new filter syntaxes
- Extending the instruction set
- Optimizing performance
- Enhancing documentation

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

## Related Projects

- [jNetWorks SDK](link-to-sdk) - Core networking SDK
- [compiler-api](link-to-compiler-api) - AST and IR generation framework

## Contact

- Issues: [GitHub Issues](link-to-issues)
- Email: [jnetruntime-dev@googlegroups.com](mailto:jnetruntime-dev@googlegroups.com)

---
