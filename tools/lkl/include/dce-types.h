#ifndef _DCE_TYPES_H_
#define _DCE_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/* Add structure list */
enum SimDevFlags {
  SIM_DEV_NOARP         = (1 << 0),
  SIM_DEV_POINTTOPOINT  = (1 << 1),
  SIM_DEV_MULTICAST     = (1 << 2),
  SIM_DEV_BROADCAST     = (1 << 3),
};

struct SimSysIterator {
};

struct SimSysFile {
};

#ifdef __cplusplus
}
#endif

struct DceKernel;
struct DceSocket;
#endif /* DCE_TYPES_SEEN*/

