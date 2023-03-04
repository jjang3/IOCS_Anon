SECTIONS
{
    .isolate_data BLOCK(4096) : ALIGN(4096) {
        _start_isolate_data = .;
            *(.isolate_data)
        _end_isolate_data = .;
    }

    .isolate_target BLOCK(4096) : ALIGN(4096) {
    _start_isolate_target = .;
            *(.isolate_target)
    _end_isolate_target = .;
    }
    
}

INSERT AFTER .rodata;