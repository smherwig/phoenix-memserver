#ifndef _SMUF_H__
#define _SMUF_H_

#include <stdint.h>

#include <rho/rho_decls.h>

RHO_DECLS_BEGIN

#define SMUF_OP_NEW_FDTABLE    0
#define SMUF_OP_FORK           1
#define SMUF_OP_CHILD_ATTACH   2
#define SMUF_OP_OPEN           3
#define SMUF_OP_CLOSE          4
#define SMUF_OP_LOCK           5
#define SMUF_OP_UNLOCK         6
#define SMUF_OP_MMAP           7

#define SMUF_MAX_NAME_SIZE          128
#define SMUF_MAX_PATH_SIZE          256
#define SMUF_MAX_ASSOCDATA_SIZE     128

#define SMUF_LOCKFILE_SIZE          4096

#define SMUF_NO_OWNER ((uint64_t)(-1))

RHO_DECLS_END


#endif /* _SMUF_H_ */
