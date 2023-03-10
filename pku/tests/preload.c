#include <stdio.h>

const void *__text_start;
const void *__text_end;

static __attribute__((constructor)) void init(void) 
{
  printf("%p to %p\n", &__text_start, &__text_end);

}