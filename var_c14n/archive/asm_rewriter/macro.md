In Intel assembly language, certain instructions automatically adjust their operation based on the operand size, which is often indicated by the register used in the instruction. This feature is part of the x86 architecture's support for variable operand sizes. Here are some key points:

### Operand-Size Dependent Instructions
1. **Arithmetic Operations**: Instructions like `ADD`, `SUB`, `MUL`, `DIV`, and their variations often adjust their operation based on whether the register is 8-bit (`AL`, `BL`, `CL`, `DL`), 16-bit (`AX`, `BX`, `CX`, `DX`), 32-bit (`EAX`, `EBX`, `ECX`, `EDX`), or 64-bit (`RAX`, `RBX`, `RCX`, `RDX`). 
   
2. **Data Movement**: Instructions like `MOV` also adjust their operation based on the operand size. For example, `MOV %AL, %BL` moves an 8-bit value, while `MOV %EAX, %EBX` moves a 32-bit value.

3. **Bitwise Operations**: Instructions like `AND`, `OR`, `XOR`, `NOT` work similarly, adjusting the operation based on operand size.

4. **Shift and Rotate**: Instructions like `SHL`, `SHR`, `ROL`, `ROR` also adjust according to the size of the register.

### How It Works
- The size of the operation is typically determined by the size of the destination operand. For instance, if you use `AX` or `EAX` or `RAX` in an arithmetic operation, the CPU will perform a 16-bit, 32-bit, or 64-bit operation respectively.
- In many cases, using a 16-bit register (`AX`, `BX`, `CX`, `DX`) automatically implies the use of their 16-bit versions, while using `EAX`, `EBX`, `ECX`, `EDX` implies their 32-bit versions, and `RAX`, `RBX`, `RCX`, `RDX` their 64-bit versions.

### Special Considerations
- **Implicit Zero-Extension**: In 64-bit mode, using a 32-bit register (`EAX`, `EBX`, etc.) for an operation automatically zero-extends the result to the corresponding 64-bit register (`RAX`, `RBX`, etc.). This is not the case when using 8-bit or 16-bit registers.
- **Prefixes for Operand Size**: In some cases, operand-size override prefixes can be used in assembly to explicitly specify the operand size different from the default.
- **Legacy and Compatibility Modes**: The behavior can vary slightly in legacy (16-bit) and compatibility (32-bit) modes compared to 64-bit mode.

Understanding these behaviors is crucial for writing efficient and correct assembly code, especially when dealing with operations that depend on operand size.