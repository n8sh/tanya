	.text


// logf.
	.globl _D5tanya4math8nbtheory4logfFNaNbNiNffZf
	.type _D5tanya4math8nbtheory4logfFNaNbNiNffZf, @function

_D5tanya4math8nbtheory4logfFNaNbNiNffZf:
	movss %xmm0, -4(%rsp) // Put the argument onto the stack

	fldln2 // Put lb(e) onto the FPU stack
	flds -4(%rsp) // Put a float onto the FPU stack
	fyl2x // %st1 * lb(%st0)

	 // The result is on the FPU stack, but returned in %xmm0
	fstps -4(%rsp)
	movss -4(%rsp), %xmm0

	ret


// log.
	.globl _D5tanya4math8nbtheory3logFNaNbNiNfdZd
	.type _D5tanya4math8nbtheory3logFNaNbNiNfdZd, @function

_D5tanya4math8nbtheory3logFNaNbNiNfdZd:
	movsd %xmm0, -8(%rsp) // Put the argument onto the stack

	fldln2 // Put lb(e) onto the FPU stack
	fldl -8(%rsp) // Put a double onto the FPU stack
	fyl2x // %st1 * lb(%st0)

	 // The result is on the FPU stack, but returned in %xmm0
	fstpl -8(%rsp)
	movsd -8(%rsp), %xmm0

	ret


// logl.
	.globl _D5tanya4math8nbtheory4loglFNaNbNiNfeZe
	.type _D5tanya4math8nbtheory4loglFNaNbNiNfeZe, @function

_D5tanya4math8nbtheory4loglFNaNbNiNfeZe:
	fldln2 // Put lb(e) onto the FPU stack
	fldt 8(%rsp) // Put the argument onto the FPU stack
	fyl2x // %st1 * lb(%st0)
	ret
