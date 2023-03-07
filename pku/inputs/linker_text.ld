SECTIONS
{
    .text BLOCK(4096) : ALIGN(4096) {
        _start_text = .;
            *(.text)
        _end_text = .;
    }
}
INSERT AFTER .rodata;