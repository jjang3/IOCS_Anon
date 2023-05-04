SECTIONS
{  
    .text BLOCK(4096) : ALIGN(4096)
    {
        __text_start = .;
            *(.text)
        __text_end = .;
    }
    .fini : 
    {
        __fini_begin = .;
            *(.fini)
        __fini_end = .;
    } 
    .isolated_target : AT(__fini_end)
    {
        _start_isolated_target = .;
            *(.isolated_target)
        _end_isolated_target = .;
    } 
} INSERT BEFORE .eh_frame_hdr;