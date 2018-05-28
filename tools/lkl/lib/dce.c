#include "dce-init.h"

extern struct DceImport g_import;
extern struct DceExport g_export;

extern lkl_init (struct DceExport *export, struct DceImport *import, struct DceKernel *kernel);

void dce_init (struct DceExport *export, struct DceImport *import, struct DceKernel *kernel)
{
  lkl_init (export, import, kernel);
  //TODO: atexit for import functions
}
