#include <stdio.h>
#include <malloc.h>
#include <pthread.h>

#include "3rdtest.h"

/* Prototypes for our hooks.  */
static void my_init_hook(void);
static void *my_malloc_hook(size_t, const void *);

/* Variables to save original hooks. */
static void *(*old_malloc_hook)(size_t, const void *);

/* Override initializing hook from the C library. */
void (*__malloc_initialize_hook) (void) = my_init_hook;

pthread_mutex_t mutex1;
static void
my_init_hook(void)
{
    printf("in my_init_hook __malloc_hook:%p \n", __malloc_hook);
    old_malloc_hook = __malloc_hook;
    __malloc_hook = my_malloc_hook;
    pthread_mutex_init(&mutex1, NULL);
}

static void *
my_malloc_hook(size_t size, const void *caller)
{
    void *result;

    // pthread_mutex_lock(&mutex1);
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
    // pthread_mutex_unlock(&mutex1);
    return result;
}

void sotest_malloc(){
    printf("%s begin\n", __FUNCTION__);
    int *a = (int *)malloc(10);
    int *c = (int *)malloc(20);
    int *b = new int;
    printf("%s end\n", __FUNCTION__);
}