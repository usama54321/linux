#ifndef DCE_HANDLE_API_H
#define DCE_HANDLE_API_H

#include <linux/types.h>
#include "dce-types.h"

/*
 * APIs to access DceHandle function
 * from Linux kernel.
 *
 * These APIs helps to avoid the use
 * global DceHandle (g_dceHandle) object
 * inside LKL.
 *
 * The objective of these APIs is
 * provide access to DceHandle functions
 * all across the Dce file inside the LKL.
 */

int lib_vprintf(const char *str, va_list args);
void *lib_malloc(unsigned long size);
void lib_free(void *buffer);
void *lib_memcpy(void *dst, const void *src, unsigned long size);
void *lib_memset(void *dst, char value, unsigned long size);

#endif /* DCE_HANDLE_API_H */

