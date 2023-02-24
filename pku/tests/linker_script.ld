SECTIONS
{
    _start_isolate_sec = .;
    .isolate_target BLOCK(4096) : ALIGN(4096) {
            *(.isolate_target)
    }
    _end_isolate_sec = .;
}

INSERT AFTER .rodata;