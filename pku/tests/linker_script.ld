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
    fini_begin = .;
    *(.fini)
    fini_end = .;
    } 
    .rodata :
    {
    *(.rodata)
    rodata_end = .;
    } 
    .isolated_target : 
    {
        _start_isolated_target = .;
            *(.isolated_target)
        _end_isolated_target = .;
    } 
} INSERT BEFORE .eh_frame_hdr;