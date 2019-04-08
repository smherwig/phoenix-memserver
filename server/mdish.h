#ifndef _MDISH_H__
#define _MDISH_H_

/*
 * REQUEST TYPES
 */

#define MDISH_OP_FILE_OPEN    0
#define MDISH_OP_FILE_CLOSE   1
#define MDISH_OP_FILE_ADVLOCK 2
#define MDISH_OP_MMAP         3
#define MDISH_OP_MUNMAP       4
#define MDISH_OP_FORK         5
#define MDISH_OP_CHILD_ATTACH 6
#define MDISH_OP_NEW_FDTABLE  7

/*
 * LOCK OPERATIONS
 */
#define MDISH_LOCKOP_LOCK       1
#define MDISH_LOCKOP_UNLOCK     2


#define MDISH_NO_OWNER ((uint64_t)(-1))

/*
 * LIMITS
 */
#define MDISH_MAX_NAME_LENGTH   255

/*
 * RESPONSE TYPES
 */

#define MDISH_RESPONSE_TYPE_RPC_ERROR  1
#define MDISH_RESPONSE_TYPE_APP_ERROR  2

/*
 * RPC ERROR
 *
 * XXX: Not sure is this is needed; essentially, all RPC errors
 * are generically a "bad request" error.
 */

#define MDISH_RPC_ERROR_BAD_OPCODE  1
#define MDISH_RPC_ERROR_BAD_BODY   2


/*
 * LIMITS
 */

#define MDISH_HEADER_LENGTH            8

/*
 * ERRORS
 */
/* XXX: use an errno value that isn't taken */
#define MDISH_ERPC                     999

#endif /* _MDISH_H_ */
