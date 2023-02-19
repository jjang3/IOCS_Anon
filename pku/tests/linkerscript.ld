SECTIONS
{
    .isolate_target ALIGN(4096) : {
            *(.isolate_target)
	        }
		}

INSERT AFTER .text;
