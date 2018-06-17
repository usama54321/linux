#include "dce-init.h"

extern struct DceImport g_import;
extern struct DceExport g_export;

extern lkl_init (struct DceExport *exported, struct DceImport *imported, struct DceKernel *kernel);

void dce_init (struct DceExport *exported, struct DceImport *imported, struct DceKernel *kernel)
{
  lkl_init (exported, imported, kernel);
  /* TODO: atexit for import functions */
}
