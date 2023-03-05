SECTIONS
{
    .isolated_data BLOCK(4096) : ALIGN(4096) {
        _start_isolated_data = .;
            *(.isolated_data)
        _end_isolated_data = .;
    }
    .protected BLOCK(4096) : ALIGN(4096) {
        _start_protected_sec = .;
            *(.protected)
        _end_protected_sec = .;
    }
    .untrusted BLOCK(4096) : ALIGN(4096) {
        _start_untrusted_sec = .;
            *(.untrusted)
        _end_untrusted_sec = .;
    }
    
}
INSERT AFTER .rodata;