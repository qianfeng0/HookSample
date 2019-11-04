#include <stdio.h>
#include <malloc.h>
#include <pthread.h>

#include "testso.h"


void sotest_malloc(){
    printf("===%s begin===\n", __FUNCTION__);
    int *a = (int *)malloc(10);
    int *c = (int *)malloc(20);
    int *b = new int[10];
    printf("===%s end===\n", __FUNCTION__);
}