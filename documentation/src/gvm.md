# Gateway Virtual Machine (GVM): A Comprehensive Overview

The **Gateway Virtual Machine (GVM)** is a specialized blockchain execution environment that rethinks how smart contracts run by integrating privacy at its core. Building on Ethereum’s Virtual Machine (EVM) model, the GVM transforms the standard transparent computation into a privacy-first system. It does so by leveraging secure multi-party computation (2PC) and garbled circuits, enabling encrypted state operations and secure contract execution. This document consolidates the key concepts, architectural changes, and integration details—especially regarding the `circuit-sdk`—to provide a comprehensive understanding for developers and machine learning models alike.

---

## 1. What Is the Gateway Virtual Machine?

### 1.1. Core Concept
The GVM extends the conventional EVM by:
- **Transpiling Opcodes to MPC Circuits:** Every standard opcode (arithmetic, logical, memory, and control flow) is translated into an equivalent operation within a secure multiparty computation (MPC) circuit.  
- **Ensuring Privacy by Default:** Instead of having public contract data, all inputs, state variables, and operations are encrypted. This guarantees that even while the blockchain verifies the correctness of state transitions, no single party has access to the plain data.
- **Using 2PC with Garbled Circuits:** A dedicated committee of nodes executes these MPC circuits via protocols (such as WRK17) so that the underlying computations remain hidden from any individual participant.

### 1.2. Why Build a Custom VM?
- **Privacy-Centric Execution:** Ethereum’s design assumes full transparency of state and operations. While zero-knowledge proofs and privacy layers exist, integrating privacy directly into the execution model is non-trivial. GVM is built from the ground up to ensure that every computation is secure.
- **Shared Private State:** Traditional blockchains expose state data to all. In contrast, the GVM maintains a shared, encrypted state that only authorized nodes (or a majority of them) can decrypt collaboratively.
- **Seamless Developer Experience:** Despite deep architectural changes, developers can continue writing Solidity or even standard Rust functions. The underlying system automatically handles the translation into secure MPC circuits without altering the conventional development workflow.

---

## 2. High-Level Architecture and Workflow

### 2.1. End-to-End Flow
The GVM execution process is best understood as a multi-stage pipeline:
  
1. **Smart Contract Development**
   - **Write Code:** Developers write contracts in Solidity or Rust (using the provided attribute macro for encryption).
   - **Compile to EVM Bytecode:** Standard toolchains (like Hardhat or Remix) compile the code into conventional EVM bytecode.
  
2. **Transpilation to MPC Circuits**
   - **Opcode Mapping:** Each EVM opcode is mapped to an equivalent MPC circuit. For example:
     - **Arithmetic Operations:** `ADD`, `SUB`, etc., are converted into arithmetic circuits operating on encrypted values.
     - **Logical/Bitwise Operations:** Instructions like `AND`, `XOR`, etc., become boolean MPC circuits.
     - **Memory and Storage Access:** Read/write operations are replaced with encrypted state accesses.
     - **Control Flow:** Branching and looping operations are handled via multiplexer (MUX) based circuits.
  
3. **Encrypted Execution**
   - **Input Encryption:** Before execution, inputs are encrypted (e.g., via secret sharing and public-key schemes) so that no single node can see the cleartext.
   - **MPC Committee Execution:** A committee of nodes collaboratively evaluates the built MPC circuit using a 2PC garbled circuits protocol (e.g., WRK17), ensuring that all intermediate values remain confidential.
  
4. **Output and State Update**
   - **Encrypted Outputs:** The MPC execution yields encrypted outputs, which include the updated contract state.
   - **On-Chain Storage:** The new, encrypted state is then recorded on-chain.
   - **Optional Decryption:** If required (with proper authorization), a subset of operations can re-encrypt or reveal specific outputs via collaboration of the MPC committee.

*Illustrative Flow:*

```plaintext
Solidity Code → EVM Bytecode → MPC Circuit Transpilation → Encrypted Execution via 2PC → Encrypted State Update on-chain
```

---

## 3. Integration with the Circuit-SDK

A key innovation behind the GVM is its seamless integration with a custom circuit system—the **`circuit-sdk`**. This integration is crucial for securely translating and executing EVM operations over encrypted data.

### 3.1. Circuit Builder in the EVM Context

- **Enhanced EVM Context:**  
  The GVM augments the standard EVM context (e.g., in `revm/src/context/evm_context.rs`) with a new field:
  ```rust
  pub circuit_builder: Rc<RefCell<WRK17CircuitBuilder>>,
  ```
  This circuit builder is responsible for accumulating “gate” instructions that represent the encrypted operations.

- **Recording Operations:**  
  During opcode execution, instead of performing operations directly on cleartext data, the GVM “records” these operations via the circuit builder. For instance, an addition operation on balances is translated into a series of gate instructions, which are later compiled into an MPC circuit.

### 3.2. WRK17 Circuit Builder

Located within the `circuit-sdk` (e.g., `circuit-sdk/compute/src/operations/circuits/builder.rs`), the **`WRK17CircuitBuilder`** implements core functions:

- **Input Capture:**  
  The `input` method wraps incoming values (like `GarbledUint` or `GarbledBoolean`) and tracks their corresponding gate indices.
  
- **Gate Construction:**  
  Methods such as `push_xor`, `push_and`, `add`, and `mul` are used to insert arithmetic and logical gates into the circuit. Each method mirrors the intended operation of its EVM counterpart.
  
- **Circuit Compilation and Execution:**  
  Once the circuit is fully built, it is compiled and executed using an MPC protocol (based on the WRK17 technique). This step produces encrypted outputs without ever exposing cleartext intermediate values.
  
- **Robust Testing:**  
  A suite of unit tests (e.g., `test_add_three`, `test_embedded_if_else`) ensures that the constructed circuits behave as expected and that the encrypted operations yield correct results upon decryption.

### 3.3. Encrypted Macro for Function Transpilation

To bridge the gap between traditional programming and encrypted computation:
- **Procedural Macro (`#[encrypted(execute)]`):**  
  Developers can annotate Rust functions with this macro, which automatically:
  - Extracts function signatures.
  - Converts plain arguments into secure, circuit-compatible inputs.
  - Traverses and transforms the function’s abstract syntax tree (AST), replacing ordinary arithmetic and logical operations with calls to the corresponding circuit builder methods.

This macro ensures that the same code can be tested in a “plain” mode while also supporting secure execution through automatic transpilation into MPC circuits.

---

## 4. Core Changes and Their Rationale

### 4.1. Architectural Shifts

- **From Plaintext to Encrypted Computation:**  
  Instead of processing visible, plaintext data as in the standard EVM, GVM processes encrypted data. Every state transition, arithmetic operation, or storage access is encapsulated in an MPC circuit, ensuring that no single node ever sees the clear values.

- **Privacy by Default:**  
  In the GVM, privacy isn’t an add-on; it is the default mode of operation. This requires every opcode and state update to support operations on ciphertexts, fundamentally changing how computations are executed and verified.

### 4.2. Integration of a Custom Circuit-Building Layer

- **Seamless Blending with EVM:**  
  The introduction of the `WRK17CircuitBuilder` into the EVM context allows for the transparent recording of operations. Developers can continue to use familiar EVM semantics while the underlying system translates these operations into secure circuits.
  
- **Transparent Developer Experience:**  
  The modifications are designed to be largely invisible to contract developers. Solidity contracts and Rust functions remain unchanged at the source level, with the security mechanisms operating “under the hood.”

### 4.3. Enhanced Testing, Benchmarking, and CI/CD

- **Robust Verification:**  
  Extensive unit tests confirm that encrypted arithmetic and logical operations yield correct results upon decryption.
  
- **Performance Benchmarks:**  
  Benchmarks demonstrate that the GVM’s approach is not only secure but also performant—often showing significant speed improvements (12–25× faster per operation) over comparable privacy-preserving alternatives.
  
- **Automated Integration:**  
  Modern CI/CD pipelines (across multiple platforms and targets) ensure that every change in the GVM, from code formatting to secure circuit execution, is thoroughly tested and validated.

---

## 5. Final Remarks

The **Gateway Virtual Machine (GVM)** represents a bold reimagining of blockchain execution. By integrating privacy-enhancing cryptography directly into the execution model—via MPC circuits and garbled circuit protocols—the GVM transforms the way smart contracts operate. The key innovations include:

- **MPC Circuit Transpilation:**  
  Converting every EVM opcode into a secure operation that processes encrypted values.
  
- **Circuit-SDK Integration:**  
  Leveraging the `WRK17CircuitBuilder` and associated libraries to seamlessly build and execute secure circuits.
  
- **Developer-Friendly Enhancements:**  
  Procedural macros and minimal interface changes ensure that developers can write, test, and deploy contracts as usual, while benefiting from deep privacy.

In summary, the GVM is not just a fork of the Ethereum VM—it is a next-generation execution environment built for a world where privacy is the default, and secure computation is integral to every operation. This document should serve as both a technical guide and a conceptual roadmap for anyone looking to understand or contribute to the evolution of privacy-preserving blockchain technology.