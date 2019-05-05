#ifndef _SMDISH_H__
#define _SMDISH_H_

#include <stdint.h>

#include <rho/rho_decls.h>

RHO_DECLS_BEGIN

#define SMDISH_OP_NEW_FDTABLE    0
#define SMDISH_OP_FORK           1
#define SMDISH_OP_CHILD_ATTACH   2
#define SMDISH_OP_OPEN           3
#define SMDISH_OP_CLOSE          4
#define SMDISH_OP_LOCK           5
#define SMDISH_OP_UNLOCK         6
#define SMDISH_OP_MMAP           7

#define SMDISH_MAX_NAME_SIZE     256

#define SMDISH_NO_OWNER ((uint64_t)(-1))

RHO_DECLS_END


#endif /* _SMDISH_H_ */
