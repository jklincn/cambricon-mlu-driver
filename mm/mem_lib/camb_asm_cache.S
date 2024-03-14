.globl	camb_flush_dcache_range
.globl	camb_clean_dcache_range
.globl	camb_inv_dcache_range

.macro func _name, _align=2
	.cfi_sections .debug_frame
	.section .text.asm.\_name, "ax"
	.type \_name, %function
	/*
	 * .cfi_startproc and .cfi_endproc are needed to output entries in
	 * .debug_frame
	 */
	.cfi_startproc
	.align \_align
	\_name:
.endm

	/*
	 * This macro is used to mark the end of a function.
	 */
.macro endfunc _name
	.cfi_endproc
	.size \_name, . - \_name
.endm

.macro	dcache_line_size  reg, tmp
	mrs	\tmp, ctr_el0
	ubfx	\tmp, \tmp, #16, #4
	mov	\reg, #4
	lsl	\reg, \reg, \tmp
.endm

/*
 * This macro can be used for implementing various data cache operations `op`
 */
.macro do_dcache_maintenance_by_mva op
	/* Exit early if size is zero */
	cbz	x1, exit_loop_\op
	dcache_line_size x2, x3
	add	x1, x0, x1
	sub	x3, x2, #1
	bic	x0, x0, x3
loop_\op:
	dc	\op, x0
	add	x0, x0, x2
	cmp	x0, x1
	b.lo    loop_\op
	dsb	sy
exit_loop_\op:
	ret
.endm

	/* ------------------------------------------
	 * Clean+Invalidate from base address till
	 * size. 'x0' = addr, 'x1' = size
	 * ------------------------------------------
	 */
func camb_flush_dcache_range
	do_dcache_maintenance_by_mva civac
endfunc camb_flush_dcache_range

	/* ------------------------------------------
	 * Clean from base address till size.
	 * 'x0' = addr, 'x1' = size
	 * ------------------------------------------
	 */
func camb_clean_dcache_range
	do_dcache_maintenance_by_mva cvac
endfunc camb_clean_dcache_range

	/* ------------------------------------------
	 * Invalidate from base address till
	 * size. 'x0' = addr, 'x1' = size
	 * ------------------------------------------
	 */
func camb_inv_dcache_range
	//do_dcache_maintenance_by_mva ivac
	b	camb_flush_dcache_range
endfunc camb_inv_dcache_range

