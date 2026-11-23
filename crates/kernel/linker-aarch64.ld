OUTPUT_FORMAT(elf64-littleaarch64)

ENTRY(_start)

PHDRS
{
    limine_requests PT_LOAD FLAGS(6); /* PF_R | PF_W */
    text            PT_LOAD FLAGS(5); /* PF_R | PF_X */
    rodata          PT_LOAD FLAGS(4); /* PF_R */
    data            PT_LOAD FLAGS(6); /* PF_R | PF_W */
    dynamic         PT_DYNAMIC;
}

SECTIONS
{
    /* Higher-half PIE base address — Limine applies KASLR slide automatically for ET_DYN kernels */
    . = 0xffffffff80000000;

    .limine_requests : {
        KEEP(*(.requests_start_marker))
        KEEP(*(.requests))
        KEEP(*(.requests_end_marker))
    } :limine_requests

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .text : {
        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    .rela.dyn : {
        *(.rela.dyn .rela.*)
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .data : {
        *(.data.rel.ro .data.rel.ro.*)
        *(.got .got.*)
        *(.data .data.*)
    } :data

    .dynamic : {
        *(.dynamic)
    } :data :dynamic

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
    }
}
