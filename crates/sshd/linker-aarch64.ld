OUTPUT_FORMAT(elf64-littleaarch64)

ENTRY(_start)

PHDRS
{
    text    PT_LOAD FLAGS(5); /* PF_R | PF_X */
    rodata  PT_LOAD FLAGS(4); /* PF_R */
    data    PT_LOAD FLAGS(6); /* PF_R | PF_W */
    dynamic PT_DYNAMIC;
}

SECTIONS
{
    /* PIE (ET_DYN) base 0x0 — kernel ELF loader applies randomized ASLR load_base + R_AARCH64_RELATIVE */
    . = 0x0000000000000000;

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
