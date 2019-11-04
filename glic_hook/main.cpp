#include <stdio.h>
#include <malloc.h>
#include <pthread.h>
#include <unistd.h>

#include "3rdtest.h"

#if (0)
/* Prototypes for our hooks.  */
static void my_init_hook(void);
static void *my_malloc_hook(size_t, const void *);

/* Variables to save original hooks. */
static void *(*old_malloc_hook)(size_t, const void *);

/* Override initializing hook from the C library. */
void (*__malloc_initialize_hook) (void) = my_init_hook;

static void
my_init_hook(void)
{
    printf("in my_init_hook __malloc_hook:%p \n", __malloc_hook);
    old_malloc_hook = __malloc_hook;
    __malloc_hook = my_malloc_hook;
}

static void *
my_malloc_hook(size_t size, const void *caller)
{
    void *result;

    /* Restore all old hooks */
    __malloc_hook = old_malloc_hook;

    /* Call recursively */
    result = malloc(size);

    /* Save underlying hooks */
    old_malloc_hook = __malloc_hook;

    /* printf() might call malloc(), so protect it too. */
    printf("malloc(%u) called from %p returns %p\n",
            (unsigned int) size, caller, result);

    /* Restore our own hooks */
    __malloc_hook = my_malloc_hook;

    return result;
}
#endif

pthread_t t1;
pthread_t t2;

void* thread1(void* arg)
{
    printf("%s begin\n", __FUNCTION__);
    // usleep(2);
    for(int i = 0; i < 100; i++){
        printf("thread1 malloc ");
        malloc(i);
    }
    printf("%s end\n", __FUNCTION__);
    return NULL;
}

void* thread2(void* arg)
{
    printf("%s begin\n", __FUNCTION__);

    for (int i = 501; i < 600; i++){
        printf("thread2 malloc ");
        malloc(i);
    }

    printf("%s end\n", __FUNCTION__);
    return NULL;
}

int main(){
    printf("hello\n");
    int *a = (int *)malloc(10);
    int *c = (int *)malloc(20);
    int *b = new int;

    sotest_malloc();

    // pthread_create(&t1, NULL, thread1, NULL);
    // pthread_create(&t2, NULL, thread2, NULL);
    // printf("pthread_create end\n");
    // pthread_join(t1, NULL);
    // pthread_join(t2, NULL);
    return 0;
}