SECTIONS
{
    _smysection = .;
    .isolate_target BLOCK(4096) : ALIGN(4096) {
            *(.isolate_target)
    }
    _emysection = .;
}

INSERT AFTER .rodata;