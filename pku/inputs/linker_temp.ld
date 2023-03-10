SECTIONS
{
    .text BLOCK(4096) : ALIGN(4096)
    {
    __text_start = .;
        *(.text)
    __text_end = .;
    }
}
INSERT BEFORE .fini;