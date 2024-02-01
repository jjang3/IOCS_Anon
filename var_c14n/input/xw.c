#include <stdio.h>

 

#define FLAG

 

#ifndef FLAG

typedef struct cat {

                int name;

                int color;

} cat_t;

#else

struct cat {

                int name;

                int color;

} cat_t;

#endif

 

#ifndef FLAG

void f(cat_t c)

#else

void f(struct cat *c, int *name, int *color)

#endif

{
                c->color = 13;
                int test = 17;
                *color = 71;
                printf("name %d, color %d\n", name, color);

}

 

int main()

{

#ifndef FLAG

                cat_t marly;

#else
                int local_name;
                int local_color;

                struct cat marly;

#endif
                struct cat testy;
                testy = marly;

                int testy2 = marly.name;

                // marly.name = 1;

                // marly.color = 2;

                // marly.name = marly.color;
                // marly.color = marly.name;

                // local_name = marly.name;
                // local_color = marly.color;

                f(&marly, &marly.name, &marly.color);

                marly.name = marly.color;
                marly.color = marly.name;

                return 0;

}