
## How to use (To-do)
1) `cd var_c14n` - Change directory to `var_c14n`
2) `bash ibcs.sh {input}` - This will load the `ibcs` under the assumption you have the source code in the `/home/ARCS/var_c14n/input` directory (e.g., `{input}.c`)
3) Once you build using `ibcs.sh`, result directory will be created with the file name `/home/ARCS/var_c14n/result/${input}`.
4) Modify `table.c` as needed depending on the number of variables you want to support `#define VAR_COUNT`.
5) Inside `/home/ARCS/var_c14n/result/${input}`, you can make the relocation table by `make lib`
6) Modify `{input}.s` inside the directory, and then after modifying the assembly code with necessary macros, you can do `make ${input}.new` to reassemble it into relocated binary

## Example of how to use macro from below:
```
    #   The replaced instruction 
    #   leaq	-1056(%rbp), %rax
    lea_gs	%rax, 0

    #   The replaced instruction 
    #   movq	%rdx, -56(%rbp)
    mov_store_gs	%rdx, 8, 64

    #   The replaced instruction
    #	movq	-56(%rbp), %rax
    mov_load_gs	%rax, 8, 64
```
> `leaq -1056(%rbp), %rax` is the original instruction, this can be replaced with macro `lea_gs %rax, 0` where the format looks like this: `.macro lea_gs dest, offset`
> Assembly codes are in AT&T format, so it is `opcode src dest`
> Offsets are by 8 bytes, read the paper for more detail (`0` -> `8` -> `16`)
> There are two types of macros that need to be used for specific opcode: `load` and `store`.

## Available macros
```
# var_c14n macros
# Load effective address macro
.macro lea_gs dest, offset
	rdgsbase %r11
	mov   \offset(%r11), %r11
	lea   (%r11), \dest
	xor   %r11, %r11
.endm

.macro lea_store_gs src, offset
	leaq  \src, %r11
	movq  (%r11), %r10
	rdgsbase %r11
	movq  \offset(%r11), %r11
	movq  %r10, (%r11)
	xor   %r10, %r10
	xor   %r11, %r11
.endm

# Data movement macros
.macro mov_store_gs src, offset, value
	rdgsbase %r11
	mov \offset(%r11), %r11
	.if \value == 8
		movb \src, (%r11)  # 8-bit 
	.elseif \value == 16
		movw \src, (%r11)  # 16-bit
	.elseif \value == 32
		movl \src, (%r11)  # 32-bit
	.elseif \value == 64
		movq \src, (%r11)  # 64-bit
	.endif
	xor   %r11, %r11
.endm

.macro mov_load_gs dest, offset, value
	rdgsbase %r11
	mov \offset(%r11), %r11
	.if \value == 8
		movb (%r11), \dest  # 8-bit 
	.elseif \value == 16
		movw (%r11), \dest  # 16-bit
	.elseif \value == 32
		movl (%r11), \dest  # 32-bit
	.elseif \value == 64
		movq (%r11), \dest  # 64-bit
	.endif
	xor   %r11, %r11
.endm

.macro mov_arr_store_gs src, offset, disp, value
	rdgsbase %r11
	mov \offset(%r11), %r11
	add \disp, %r11
	.if \value == 8
		movb \src, (%r11)  # 8-bit 
	.elseif \value == 16
		movw \src, (%r11)  # 16-bit 
	.elseif \value == 32
		movl \src, (%r11)  # 32-bit 
	.elseif \value == 64
		movq \src, (%r11)  # 64-bit 
	.endif
	xor   %r11, %r11
.endm

.macro mov_arr_load_gs src, offset, disp, value
	rdgsbase %r11
	mov \offset(%r11), %r11
	add \disp, %r11
	.if \value == 8
		movb (%r11), \dest  # 8-bit
	.elseif \value == 16
		movw (%r11), \dest  # 16-bit
	.elseif \value == 32
		movl (%r11), \dest  # 32-bit
	.elseif \value == 64
		movq (%r11), \dest  # 64-bit
	.endif
	xor   %r11, %r11
.endm

.macro movss_store_gs src, offset, value
	rdgsbase %r11
	mov \offset(%r11), %r11
		movss \src, (%r11)  # 64-bit
	xor   %r11, %r11
.endm

.macro movss_load_gs dest, offset, value
	rdgsbase %r11
	mov \offset(%r11), %r11
	movss (%r11), \dest  # 64-bit
	xor   %r11, %r11
.endm

.macro movzx_load_gs dest, offset, value
	rdgsbase %r11
	mov \offset(%r11), %r11
	.if \value == 8
		movzbl (%r11), \dest  # 8-bit 
	.elseif \value == 16
		movzx (%r11), \dest  # 16-bit
	.endif
	xor   %r11, %r11
.endm

# Comparison / Shift macros
# ---- Comparison ---- #
.macro cmp_store_gs operand, offset, value
	rdgsbase %r11
	mov \offset(%r11), %r11
	.if \value == 8
		cmpb \operand, (%r11)  # 8-bit 
	.elseif \value == 16
		cmpw \operand, (%r11)  # 16-bit
	.elseif \value == 32
		cmpl \operand, (%r11)  # 32-bit
	.elseif \value == 64
		cmpq \operand, (%r11)  # 64-bit
	.endif
	xor   %r11, %r11
.endm

.macro cmp_load_gs operand, offset, value
	rdgsbase %r11
	mov \offset(%r11), %r11
	.if \value == 8
		cmpb (%r11), \operand  # 8-bit 
	.elseif \value == 16
		cmpw (%r11), \operand  # 16-bit
	.elseif \value == 32
		cmpl (%r11), \operand  # 32-bit
	.elseif \value == 64
		cmpq (%r11), \operand  # 64-bit
	.endif
	xor   %r11, %r11
.endm

.macro and_store_gs operand, offset, value
	rdgsbase %r11
	mov \offset(%r11), %r11
	.if \value == 8
		andb \operand, (%r11)  # 8-bit 
	.elseif \value == 16
		andw \operand, (%r11)  # 16-bit
	.elseif \value == 32
		andl \operand, (%r11)  # 32-bit
	.elseif \value == 64
		andq \operand, (%r11)  # 64-bit
	.endif
	xor   %r11, %r11
.endm

.macro and_load_gs operand, offset, value
	rdgsbase %r11
	mov \offset(%r11), %r11
	.if \value == 8
		andb (%r11), \operand  # 8-bit 
	.elseif \value == 16
		andw (%r11), \operand  # 16-bit
	.elseif \value == 32
		andl (%r11), \operand  # 32-bit
	.elseif \value == 64
		andq (%r11), \operand  # 64-bit
	.endif
	xor   %r11, %r11
.endm

# Arithmetic macros
# ---- Addition ---- #
.macro add_store_gs operand, offset, value
	rdgsbase %r10
	mov	\offset(%r10), %r10 
	rdgsbase %r11
	mov	\offset(%r11), %r11
	mov (%r11), %r11
	.if \value == 8
	add \operand, %r11b  # 8-bit 
	mov %r11b, (%r10)
	.elseif \value == 16
	add \operand, %r11w  # 16-bit 
	mov %r11w, (%r10)
	.elseif \value == 32
	add \operand, %r11d  # 32-bit 
	mov %r11d, (%r10)
	.elseif \value == 64
	add \operand, %r11   # 64-bit 
	mov %r11, (%r10)
	.endif
	xor   %r10, %r10
	xor   %r11, %r11
.endm

.macro add_load_gs dest, offset, value
	rdgsbase %r11
	mov \offset(%r11), %r11
	.if \value == 8
	mov (%r11), %r11b
	add %r11b, \dest  # 8-bit 
	.elseif \value == 16
	mov (%r11), %r11w
	add %r11w, \dest  # 16-bit 
	.elseif \value == 32
	mov (%r11), %r11d
	add %r11d, \dest  # 32-bit 
	.elseif \value == 64
	mov (%r11), %r11
	add %r11, \dest   # 64-bit 
	.endif
	xor   %r11, %r11
.endm

# ---- Subtraction ---- #
.macro sub_store_gs operand, offset, value
	rdgsbase %r10
	mov	\offset(%r10), %r10 
	rdgsbase %r11
	mov	\offset(%r11), %r11
	mov (%r11), %r11
	.if \value == 8
	sub \operand, %r11b  # 8-bit 
	mov %r11b, (%r10)
	.elseif \value == 16
	sub \operand, %r11w  # 16-bit 
	mov %r11w, (%r10)
	.elseif \value == 32
	sub \operand, %r11d  # 32-bit 
	mov %r11d, (%r10)
	.elseif \value == 64
	sub \operand, %r11   # 64-bit 
	mov %r11, (%r10)
	.endif
	xor   %r10, %r10
	xor   %r11, %r11
.endm

.macro sub_load_gs dest, offset, value
	rdgsbase %r11
	mov \offset(%r11), %r11
	.if \value == 8
	mov (%r11), %r11b
	sub %r11b, \dest  # 8-bit 
	.elseif \value == 16
	mov (%r11), %r11w
	sub %r11w, \dest  # 16-bit 
	.elseif \value == 32
	mov (%r11), %r11d
	sub %r11d, \dest  # 32-bit 
	.elseif \value == 64
	mov (%r11), %r11
	sub %r11, \dest   # 64-bit 
	.endif
	xor   %r11, %r11
.endm

# ---- Multiplication ---- #
.macro imul_store_gs operand, offset, value
	rdgsbase %r10
	mov	\offset(%r10), %r10 
	rdgsbase %r11
	mov	\offset(%r11), %r11
	mov (%r11), %r11
	.if \value == 8
	imul \operand, %r9b  # 8-bit 
	mov %r9b, (%r10)
	.elseif \value == 16
	imul \operand, %r9w  # 16-bit 
	mov %r9w, (%r10)
	.elseif \value == 32
	imul \operand, %r9d  # 32-bit 
	mov %r9d, (%r10)
	.elseif \value == 64
	imul \operand, %r9   # 64-bit 
	mov %r9, (%r10)
	.endif
	xor   %r9, %r9
	xor   %r10, %r10
	xor   %r11, %r11
.endm

.macro imul_load_gs dest, offset, value
	rdgsbase %r11
	mov \offset(%r11), %r11
	.if \value == 8
	mov (%r11), %r10b
	imul %r10b, \dest  # 8-bit 
	.elseif \value == 16
	mov (%r11), %r10w
	imul %r10w, \dest  # 16-bit 
	.elseif \value == 32
	mov (%r11), %r0d
	imul %r10d, \dest  # 32-bit 
	.elseif \value == 64
	mov (%r11), %r10
	imul %r10, \dest   # 64-bit 
	.endif
	xor   %r10, %r10
	xor   %r11, %r11
.endm

.macro shl_store_gs operand, offset, value
	rdgsbase %r10
	mov	\offset(%r10), %r10 
	rdgsbase %r11
	mov	\offset(%r11), %r11
	mov (%r11), %r11
	.if \value == 8
	shl \operand, %r11b  # 8-bit 
	mov %r11b, (%r10)
	.elseif \value == 16
	shl \operand, %r11w  # 16-bit 
	mov %r11w, (%r10)
	.elseif \value == 32
	shl \operand, %r11d  # 32-bit 
	mov %r11d, (%r10)
	.elseif \value == 64
	shl \operand, %r11   # 64-bit 
	mov %r11, (%r10)
	.endif
	xor   %r10, %r10
	xor   %r11, %r11
.endm
```