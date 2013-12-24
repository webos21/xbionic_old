.section .init_array, "aw"
    .long 0

.section .fini_array, "aw"
    .long 0

	.section	.eh_frame,"a"
	.align 4
__FRAME_END__:
	.zero	4
