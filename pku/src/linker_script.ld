SECTIONS
{
    .text BLOCK(4096) : ALIGN(4096)
    {
        __text_start = .;
            *(.text)
        __text_end = .;
    }
    .fini : AT (__text_end) 
    {
        __fini_begin = .;
            *(.fini)
        __fini_end = .;
    } 
    .isolated_target : AT (__fini_end)
    {
        _start_isolated_target = .;
            *(.isolated_target)
        _end_isolated_target = .;
    } 
    .rodata :
    {
            *(.rodata)
        __rodata_end = .;
    } 
} INSERT BEFORE .eh_frame_hdr;