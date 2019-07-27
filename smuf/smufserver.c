#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rho/rho.h>
#include <rpc.h>

#include "smuf.h"

/**************************************
 * TYPES
 **************************************/
struct smuf_server {
    struct rho_sock *srv_sock;
    struct rho_ssl_ctx *srv_sc;
    /* TODO: don't hardcode 108 */
    uint8_t srv_udspath[108];
};

struct smuf_memfile {
    char        f_name[SMUF_MAX_NAME_SIZE];
    int32_t     f_counter;
    int         f_client_refcnt;    /* #clients that are using this file */

    uint8_t     f_type;

    size_t      f_map_size;
    uint8_t     f_iv[SMUF_IV_SIZE];
    uint8_t     f_key[SMUF_KEY_SIZE];
    uint8_t     f_tag[SMUF_TAG_SIZE];

    RHO_RB_ENTRY(smuf_memfile) f_memfile;
};

RHO_RB_HEAD(smuf_memfile_tree, smuf_memfile);

struct smuf_desctable {
    struct rho_bitmap *dt_map;
    /* array of pointers to open memfiles */
    struct smuf_memfile **dt_openmemfiles;
};

struct smuf_client {
    RHO_LIST_ENTRY(smuf_client) cli_next_client;
    struct rpc_agent        *cli_agent;
    struct smuf_desctable *cli_fdtab;
    uint64_t                cli_id;
};

RHO_LIST_HEAD(smuf_client_list, smuf_client);

typedef void (*smuf_opcall)(struct smuf_client *client);

/**************************************
 * FORWARD DECLARATIONS
 **************************************/

/* memfile tree */
static int smuf_memfile_cmp(struct smuf_memfile *a,
        struct smuf_memfile *b);

static struct smuf_memfile * smuf_memfile_tree_find(const char *name);
static struct smuf_memfile * smuf_memfile_create(const char *name, int *error);

/* memfile */
static void smuf_memfile_destroy(struct smuf_memfile *mf);

static int smuf_memfile_open_or_create(struct smuf_client *client,
        const char *name, uint32_t *fd);

static int smuf_memfile_close(struct smuf_client *client, uint32_t fd);

static int smuf_memfile_add_map(struct smuf_client *client, uint32_t fd, 
        uint32_t size);

/* rpc handlers */
static void smuf_new_fdtable_proxy(struct smuf_client *client);
static void smuf_fork_proxy(struct smuf_client *client);
static void smuf_child_attach_proxy(struct smuf_client *client);
static void smuf_open_proxy(struct smuf_client *client);
static void smuf_close_proxy(struct smuf_client *client);
static void smuf_lock_proxy(struct smuf_client *client);
static void smuf_unlock_proxy(struct smuf_client *client);
static void smuf_mmap_proxy(struct smuf_client *client);

/* desctable */
static struct smuf_desctable * smuf_desctable_create(void);
static void smuf_desctable_expand(struct smuf_desctable *tab);
static int smuf_desctable_descalloc(struct smuf_desctable *tab);
static int smuf_desctable_setopenmemfile(struct smuf_desctable *tab,
        struct smuf_memfile *mf);

static struct smuf_memfile * smuf_desctable_getmemfile(
        struct smuf_desctable *tab, uint32_t fd);

/* 
 * desctable: specific functions locks files (fdtable)
 */
static struct smuf_desctable * smuf_fdtable_copy(
        const struct smuf_desctable *fdtab);

static void smuf_client_fdtable_destroy(struct smuf_client *client);

/* client */
static struct smuf_client * smuf_client_find(uint64_t id);
static void smuf_client_add(struct smuf_client *client);
static struct smuf_client * smuf_client_alloc(void);
static struct smuf_client * smuf_client_create(struct rho_sock *sock);
static struct smuf_client * smuf_client_fork(struct smuf_client *parent);

static void smuf_client_splice(struct smuf_client *a, 
        struct smuf_client *b);

static void smuf_client_destroy(struct smuf_client *client);
static void smuf_client_dispatch_call(struct smuf_client *client);

static void smuf_client_cb(struct rho_event *event, int what,
        struct rho_event_loop *loop);

/* server */
static struct smuf_server * smuf_server_alloc(void);
static void smuf_server_destroy(struct smuf_server *server);

static void smuf_server_config_ssl(struct smuf_server *server,
        const char *cafile, const char *certfile, const char *keyfile);

static void smuf_server_socket_create(struct smuf_server *server,
        const char *udspath, bool anonymous);

static void smuf_server_cb(struct rho_event *event, int what,
        struct rho_event_loop *loop);

/* log */
static void smuf_log_init(const char *logfile, bool verbose);

/* usage */
static void
usage(int exitcode);

/**************************************
 * GLOBALS
 **************************************/

struct rho_log *smuf_log = NULL;
const char *smuf_root = NULL;

struct smuf_memfile_tree smuf_memfile_tree_root = 
        RHO_RB_INITIALIZER(&smuf_memfile_tree_root);

static struct smuf_client_list smuf_clients =
        RHO_LIST_HEAD_INITIALIZER(smuf_clients);

static smuf_opcall smuf_opcalls[] = {
    [SMUF_OP_NEW_FDTABLE]  = smuf_new_fdtable_proxy,
    [SMUF_OP_FORK]         = smuf_fork_proxy,
    [SMUF_OP_CHILD_ATTACH] = smuf_child_attach_proxy,

    [SMUF_OP_OPEN]    = smuf_open_proxy,
    [SMUF_OP_CLOSE]   = smuf_close_proxy,
    [SMUF_OP_MMAP]    = smuf_mmap_proxy,
    [SMUF_OP_LOCK]    = smuf_lock_proxy,
    [SMUF_OP_UNLOCK]  = smuf_unlock_proxy,
};

/**************************************
 * RED-BLACK TREE OF MEMFILES
 **************************************/

static int
smuf_memfile_cmp(struct smuf_memfile *a, struct smuf_memfile *b)
{
    return (strcmp(a->f_name, b->f_name));
}

RHO_RB_GENERATE_STATIC(smuf_memfile_tree, smuf_memfile, f_memfile,
        smuf_memfile_cmp);

static struct smuf_memfile *
smuf_memfile_tree_find(const char *name)
{
    size_t n = 0;
    struct smuf_memfile key;
    struct smuf_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    n = rho_strlcpy(key.f_name, name, SMUF_MAX_NAME_SIZE);
    if (n >= SMUF_MAX_NAME_SIZE) {
        rho_warn("strlcpy truncation would occur\n");
        goto done;
    }

    mf = RHO_RB_FIND(smuf_memfile_tree, &smuf_memfile_tree_root, &key);

done:
    RHO_TRACE_EXIT();
    return (mf);
}

/**************************************
 * MEMFILE
 **************************************/

/* Returns 0 on success; an errno value on failure */
static int
smuf_create_file(const char *path, size_t size)
{
    int error = 0;
    int fd = 0;

    RHO_TRACE_ENTER("path=\"%s\", size=%zu", path, size);

    fd = open(path, O_RDWR|O_CREAT, 0644); 
    if (fd == -1) {
        error = errno;
        rho_errno_warn(errno, "open(\"%s\") failed", path);
        goto done;
    }

    error = ftruncate(fd, (off_t)size);
    if (error == -1) {
        error = errno;
        rho_errno_warn(errno, "ftruncate(\"%s\", size=%zu) failed",
                path, size);
        goto done;
    }

    error = close(fd);
    if (error == -1) {
        error = errno;
        rho_errno_warn(errno, "close(\"%s\") failed", path);
        goto done;
    }
    
done:
    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

/* Returns 0 on success; an errno value on failure */
static int
smuf_delete_file(const char *path)
{
    int error = 0;

    RHO_TRACE_ENTER("path=\"%s\"", path);

    error = unlink(path);
    if (error == -1) {
        error = errno;
        rho_errno_warn(errno, "unlink(\"%s\") failed", path);
    }

    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static void
smuf_memfile_get_lockfile_path(const struct smuf_memfile *mf,
        char *path, size_t path_size)
{
    size_t n = 0;

    RHO_TRACE_ENTER("mf->f_name=\"\%s\"", mf->f_name);

    if (smuf_root != NULL) {
        /* FIXME: check for errors, bounds detection */
         rho_path_join(smuf_root, mf->f_name, path, path_size);
    } else {
        n = rho_strlcpy(path, mf->f_name, path_size);
        RHO_ASSERT(n < path_size);
    }

    RHO_TRACE_EXIT("path=\"%s\"", path);
}

/* Returns 0 on success; an errno value on failure */
static int
smuf_memfile_create_lockfile(const struct smuf_memfile *mf)
{
    int error = 0;
    char path[SMUF_MAX_PATH_SIZE] = { 0 };

    RHO_TRACE_ENTER();

    smuf_memfile_get_lockfile_path(mf, path, sizeof(path));
    error = smuf_create_file(path , SMUF_LOCKFILE_SIZE);

    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

/* Returns 0 on success; an errno value on failure */
static int
smuf_memfile_delete_lockfile(const struct smuf_memfile *mf)
{
    int error = 0;
    char path[SMUF_MAX_PATH_SIZE] = { 0 };

    RHO_TRACE_ENTER();

    smuf_memfile_get_lockfile_path(mf, path, sizeof(path));
    error = smuf_delete_file(path);

    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static void
smuf_memfile_get_segmentfile_path(const struct smuf_memfile *mf,
        char *path, size_t path_size)
{
    size_t n = 0;

    RHO_TRACE_ENTER("mf->f_name=\"\%s\"", mf->f_name);

    if (smuf_root != NULL) {
        /* FIXME: check for errors, bounds detection */
        rho_path_join(smuf_root, mf->f_name, path, path_size);
    } else {
        n = rho_strlcpy(path, mf->f_name, path_size);
        RHO_ASSERT(n < path_size);
    }

    n = rho_strlcat(path, ".segment", path_size);
    RHO_ASSERT(n < path_size);

    RHO_TRACE_EXIT("path=\"%s\"", path);
}

/* Returns 0 on success; an errno value on failure */
static int
smuf_memfile_create_segmentfile(const struct smuf_memfile *mf)
{
    int error = 0;
    char path[SMUF_MAX_PATH_SIZE] = { 0 };

    RHO_TRACE_ENTER();

    smuf_memfile_get_segmentfile_path(mf, path, sizeof(path));
    error = smuf_create_file(path, mf->f_map_size);

    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

/* Returns 0 on success; an errno value on failure */
static int
smuf_memfile_delete_segmentfile(const struct smuf_memfile *mf)
{
    int error = 0;
    char path[SMUF_MAX_NAME_SIZE * 2] = { 0 };

    RHO_TRACE_ENTER();

    smuf_memfile_get_segmentfile_path(mf, path, sizeof(path));
    error = smuf_delete_file(path);

    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static struct smuf_memfile *
smuf_memfile_create(const char *name, int *error)
{
    int err = 0;
    size_t n = 0;
    struct smuf_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    mf = rhoL_zalloc(sizeof(*mf));

    n = rho_strlcpy(mf->f_name, name, sizeof(mf->f_name));
    RHO_ASSERT(n < sizeof(mf->f_name));

    mf->f_client_refcnt = 1;
    mf->f_type = SMUF_TYPE_PURE_LOCK;

    err = smuf_memfile_create_lockfile(mf);
    if (err != 0) {
        rhoL_free(mf);
        mf = NULL;
        if (error != NULL)
            *error = err;
    }

    RHO_TRACE_EXIT();
    return (mf);
}

static void
smuf_memfile_destroy(struct smuf_memfile *mf)
{
    RHO_TRACE_ENTER("mf->f_name=\"%s\"", mf->f_name);

    smuf_memfile_delete_lockfile(mf);
    if (mf->f_map_size > 0)
        smuf_memfile_delete_segmentfile(mf);

    RHO_TRACE_EXIT();
    return;
}

/* returns 0 on success; an errno value on error */
static int
smuf_memfile_open_or_create(struct smuf_client *client, const char *name,
        uint32_t *fd)
{
    int error = 0;
    struct smuf_desctable *fdtab = client->cli_fdtab;
    struct smuf_memfile *mf = NULL;

    RHO_TRACE_ENTER("name=\"%s\"", name);

    mf = smuf_memfile_tree_find(name);
    if (mf == NULL) {
        rho_debug("creating new file \"%s\"", name);
        mf = smuf_memfile_create(name, &error);
        if (mf == NULL)
            goto done;
        RHO_RB_INSERT(smuf_memfile_tree, &smuf_memfile_tree_root, mf);
    } else {
        rho_debug("opening existing file \"%s\"", name);
        mf->f_client_refcnt++;
    }

    *fd = smuf_desctable_setopenmemfile(fdtab, mf);

done:
    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static int
smuf_memfile_close(struct smuf_client *client, uint32_t fd)
{
    int error = 0;
    struct smuf_desctable *fdtab = client->cli_fdtab;
    struct smuf_memfile *mf = NULL;

    RHO_TRACE_ENTER("fd=%"PRIu32, fd);

    mf = smuf_desctable_getmemfile(fdtab, fd);
    if (mf == NULL) {
        error = EBADF;
        goto done;
    }

    mf->f_client_refcnt--;
    rho_debug("mf->f_client_refcnt=%d", mf->f_client_refcnt);
    if (mf->f_client_refcnt == 0) {
        RHO_RB_REMOVE(smuf_memfile_tree, &smuf_memfile_tree_root, mf);
        smuf_memfile_destroy(mf);
    }

    rho_bitmap_clear(fdtab->dt_map, fd);

done:
    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static int
smuf_memfile_add_map(struct smuf_client *client, uint32_t fd,
        uint32_t map_size)
{
    int error = 0;
    struct smuf_desctable *fdtab = client->cli_fdtab;
    struct smuf_memfile *mf = NULL;

    RHO_TRACE_ENTER("fd=%"PRIu32", map_size=%"PRIu32, fd, map_size);

    mf = smuf_desctable_getmemfile(fdtab, fd);
    if (mf == NULL) {
        error = EBADF;
        goto done;
    }

    /* XXX: what should we do if f_map_size > 0? */
    if (mf->f_map_size == 0) {

        mf->f_map_size = map_size;
        error = smuf_memfile_create_segmentfile(mf);
        if (error != 0)
            goto done;

        mf->f_type = SMUF_TYPE_LOCK_WITH_UNINIT_SEGMENT;
    }

done:
    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

/**************************************
 * RPC HANDLERS
 **************************************/

static void
smuf_new_fdtable_proxy(struct smuf_client *client)
{
    struct rpc_agent *agent = client->cli_agent;

    RHO_TRACE_ENTER();

    if (client->cli_fdtab != NULL)
        smuf_client_fdtable_destroy(client);

    client->cli_fdtab = smuf_desctable_create();

    rpc_agent_new_msg(agent, 0);

    rho_log_errno_debug(smuf_log, 0, "id=0x%"PRIx64" new_fdtable()",
        client->cli_id);

    RHO_TRACE_EXIT();
    return;
}

static void
smuf_fork_proxy(struct smuf_client *client)
{
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct smuf_client *child = NULL;
    uint64_t id = 0;

    RHO_TRACE_ENTER();

    child = smuf_client_fork(client);
    smuf_client_add(child);
    id = child->cli_id;

    rpc_agent_new_msg(agent, 0);
    rpc_agent_set_bodylen(agent, 8);
    rho_buf_writeu64be(buf, id);

    rho_log_errno_debug(smuf_log, 0, "id=0x%"PRIx64" fork() -> 0x%"PRIx64,
        client->cli_id, id);

    RHO_TRACE_EXIT();
    return;
}

static void
smuf_child_attach_proxy(struct smuf_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint64_t id;
    struct smuf_client *attachee = NULL;;

    RHO_TRACE_ENTER();

    error = rho_buf_readu64be(buf, &id);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    attachee = smuf_client_find(id);
    if (attachee == NULL) {
        rho_log_warn(smuf_log, "cannot find id 0x%"PRIx64" to attach to", id);
        error = EINVAL;
        goto done;
    }

    smuf_client_splice(client, attachee);
    
done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(smuf_log, error, "id=0x%"PRIx64" child_attach()",
        client->cli_id);

    RHO_TRACE_EXIT();
    return;
}

static void
smuf_open_proxy(struct smuf_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char name[SMUF_MAX_NAME_SIZE] = { 0 };
    uint32_t name_size = 0;
    uint32_t fd = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, &name_size);
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    if (name_size >= SMUF_MAX_NAME_SIZE) {
        error = ENAMETOOLONG;
        goto done;
    }

    /*
     * clients will ask for names like '/foo'; the server changes
     * the name to just 'foo'.
     *
     * name_size must be greater than 2 and start with a slash.
     * A slash cannot appear anywhere else in the name.
     */
    if (name_size < 2) {
        error = EINVAL;
        goto done;
    }

    if (rho_buf_read(buf, name, name_size) != name_size) {
        error = EPROTO;
        goto done;
    }

    if (name[0] != '/') {
        error = EINVAL;
        goto done;
    }

    if (strchr(name + 1, '/') != NULL) {
        error = EINVAL;
        goto done;
    }

    /* skip leading '/' */
    error = smuf_memfile_open_or_create(client, name + 1, &fd);

done:
    rpc_agent_new_msg(agent, error);
    if (error) {
        rho_log_errno_debug(smuf_log, error, "id=0x%"PRIx64" open(\"%s\")",
            client->cli_id, name);
    } else {
        rpc_agent_set_bodylen(agent, 4);
        rho_buf_writeu32be(buf, fd);
        rho_log_errno_debug(smuf_log, error,
                "id=0x%"PRIx64" open(\"%s\") -> %d",
                client->cli_id, name, fd);
    }
    RHO_TRACE_EXIT();
    return;
}

static void
smuf_close_proxy(struct smuf_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint32_t fd = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, &fd);        
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    error = smuf_memfile_close(client, fd);

done:
    rpc_agent_new_msg(agent, error);
    rho_log_errno_debug(smuf_log, error, "id=0x%"PRIx64" close(%d)",
        client->cli_id, fd);

    RHO_TRACE_EXIT();
    return;
}

static bool
smuf_valid_client_type(uint8_t type)
{
    return ((type == SMUF_TYPE_PURE_LOCK) || (type == SMUF_TYPE_LOCK_WITH_SEGMENT));

}

static bool
smuf_memfile_client_type_compatible(const struct smuf_memfile *mf,
        uint8_t type)
{
    return (
            (mf->f_type == type) || 
            
            ((mf->f_type == SMUF_TYPE_LOCK_WITH_UNINIT_SEGMENT) && 
             (type == SMUF_TYPE_LOCK_WITH_SEGMENT))
           );
}

static void
smuf_lock_proxy(struct smuf_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint32_t fd = 0;
    uint8_t type = 0; 
    int32_t expected_counter = 0;
    struct smuf_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, &fd);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_read32be(buf, &expected_counter);
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_readu8(buf, &type);
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    if (!smuf_valid_client_type(type)) {
        error = EBADE;
        goto done;
    }

    mf = smuf_desctable_getmemfile(client->cli_fdtab, fd);
    if (mf == NULL) {
        error = EBADF;
        goto done;
    }

    if (!smuf_memfile_client_type_compatible(mf, type)) {
        error = EBADE;
        goto done;
    }

    if (mf->f_counter != expected_counter) {
        rho_warn("memfile \"%s\"'s counter (%"PRId32") != client's counter (%"PRId32,
            mf->f_name, mf->f_counter, expected_counter);
        error = EINVAL;
        goto done;
    }

done:
    rpc_agent_new_msg(agent, error);
    if (!error) {
        rho_buf_writeu8(buf, mf->f_type);
        if (mf->f_type == SMUF_TYPE_LOCK_WITH_SEGMENT) {
            rho_buf_writeu32be(buf, SMUF_IV_SIZE);
            rho_buf_write(buf, mf->f_iv, SMUF_IV_SIZE);
            rho_buf_writeu32be(buf, SMUF_KEY_SIZE);
            rho_buf_write(buf, mf->f_key, SMUF_KEY_SIZE);
            rho_buf_writeu32be(buf, SMUF_TAG_SIZE);
            rho_buf_write(buf, mf->f_tag, SMUF_TAG_SIZE);
        }
        rpc_agent_autoset_bodylen(agent);
    }

    rho_log_errno_debug(smuf_log, error, 
            "id=0x%"PRIx64" lock(%"PRIu32")", client->cli_id, fd);

    RHO_TRACE_EXIT();
    return;
}

static void
smuf_unlock_proxy(struct smuf_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint32_t fd = 0;
    uint8_t type = 0;
    struct smuf_memfile *mf = NULL;
    uint32_t n = 0;
    uint8_t iv[SMUF_IV_SIZE] = { 0 };
    uint8_t key[SMUF_KEY_SIZE] = { 0 };
    uint8_t tag[SMUF_TAG_SIZE] = { 0 };

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, &fd);
    if (error == -1) {
        rho_warn("rho_buf_read failed");
        error = EPROTO;
        goto done;
    }

    error = rho_buf_readu8(buf, &type);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    if (!smuf_valid_client_type(type)) {
        error = EBADE;
        goto done;
    }

    mf = smuf_desctable_getmemfile(client->cli_fdtab, fd);
    if (mf == NULL) {
        error = EBADF;
        goto done;
    }

    if (!smuf_memfile_client_type_compatible(mf, type)) {
        error = EBADE;
        goto done;
    }

    if (mf->f_type == SMUF_TYPE_PURE_LOCK) {
        mf->f_counter += 1;
        goto done;
    }

    /* iv */
    error = rho_buf_readu32be(buf, &n);
    if ((error != 0) || (n != SMUF_IV_SIZE)) {
        error = EPROTO;
        goto done;
    }

    if (rho_buf_read(buf, iv, SMUF_IV_SIZE) != SMUF_IV_SIZE) {
        error = EPROTO;
        goto done;
    }

    /* key */
    error = rho_buf_readu32be(buf, &n);
    if ((error != 0) || (n != SMUF_KEY_SIZE)) {
        error = EPROTO;
        goto done;
    }

    if (rho_buf_read(buf, key, SMUF_KEY_SIZE) != SMUF_KEY_SIZE) {
        error = EPROTO;
        goto done;
    }

    /* tag */
    error = rho_buf_readu32be(buf, &n);
    if ((error != 0) || (n != SMUF_TAG_SIZE)) {
        error = EPROTO;
        goto done;
    }

    if (rho_buf_read(buf, tag, SMUF_TAG_SIZE) != SMUF_TAG_SIZE) {
        error = EPROTO;
        goto done;
    }

    memcpy(mf->f_iv, iv, SMUF_IV_SIZE);
    memcpy(mf->f_key, key, SMUF_KEY_SIZE);
    memcpy(mf->f_tag, tag, SMUF_TAG_SIZE);

    mf->f_type = SMUF_TYPE_LOCK_WITH_SEGMENT;
    mf->f_counter += 1;
    error = 0;

done:
    rpc_agent_new_msg(agent, error);
    rho_log_errno_debug(smuf_log, error, 
            "id=0x%"PRIx64" unlock(%"PRIu32")", client->cli_id, fd);

    RHO_TRACE_EXIT();
    return;
}

static void
smuf_mmap_proxy(struct smuf_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint32_t fd = 0;
    uint32_t map_size = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, &fd);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_readu32be(buf, &map_size);        
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    error = smuf_memfile_add_map(client, fd, map_size);

done:
    rpc_agent_new_msg(agent, error);
    rho_log_errno_debug(smuf_log, error, 
                "id=0x%"PRIx64" mmap(%"PRIu32", %"PRIu32")",
                client->cli_id, fd, map_size);

    RHO_TRACE_EXIT();
    return;
}

/**************************************
 * DESCTABLE
 **************************************/

static struct smuf_desctable *
smuf_desctable_create(void)
{
    struct smuf_desctable *tab = NULL;

    RHO_TRACE_ENTER();

    tab = rhoL_zalloc(sizeof(*tab));
    tab->dt_map = rho_bitmap_create(true, 20);
    tab->dt_openmemfiles = rhoL_mallocarray(20,
            sizeof(struct smuf_memfile *), 0);

    RHO_TRACE_EXIT();
    return (tab);
}

static void
smuf_desctable_expand(struct smuf_desctable *tab)
{
    size_t newmaxbits = 0;
    struct rho_bitmap *map = tab->dt_map;

    RHO_TRACE_ENTER();
    
    /* TODO: check for overflow; also, check that this actually
     * expands, since the range of size_t is greater than int
     */
    newmaxbits = rho_bitmap_size(map) + 32;
    rho_bitmap_resize(map, newmaxbits);
    tab->dt_openmemfiles = rhoL_reallocarray(tab->dt_openmemfiles,
            newmaxbits, sizeof(struct smuf_memfile *), 0);

    RHO_TRACE_EXIT();
}

static int
smuf_desctable_descalloc(struct smuf_desctable *tab)
{
    int d = 0;
    size_t oldmaxbits = 0;
    struct rho_bitmap *map = tab->dt_map;

    RHO_TRACE_ENTER();

    /* TODO: you might want some upper limit on how many files a client can
     * have open
     */
    d = rho_bitmap_ffc(map);
    if (d == -1) {
        oldmaxbits = rho_bitmap_size(map);
        smuf_desctable_expand(tab);
        d = oldmaxbits;
    }

    rho_bitmap_set(tab->dt_map, d);

    RHO_TRACE_EXIT("d=%d", d);
    return (d);
}

static int
smuf_desctable_setopenmemfile(struct smuf_desctable *tab,
        struct smuf_memfile *mf)
{
    int d = 0;

    RHO_TRACE_ENTER();

    d = smuf_desctable_descalloc(tab);
    tab->dt_openmemfiles[d] = mf;

    RHO_TRACE_EXIT("d=%d", d);
    return (d);
}

static struct smuf_memfile *
smuf_desctable_getmemfile(struct smuf_desctable *tab, uint32_t d)
{
    struct smuf_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    if (!rho_bitmap_isset(tab->dt_map, d))
        goto done;

    mf = tab->dt_openmemfiles[d];
    RHO_ASSERT(mf != NULL);

done:
    RHO_TRACE_EXIT();
    return (mf);
}

static struct smuf_desctable *
smuf_fdtable_copy(const struct smuf_desctable *fdtab)
{
    struct smuf_desctable *newp = NULL;
    struct smuf_memfile *mf = NULL;
    size_t fd = 0;
    int bitval = 0;
    size_t n = 0;

    RHO_TRACE_ENTER();

    newp = rhoL_zalloc(sizeof(*newp));
    newp->dt_map = rho_bitmap_copy(fdtab->dt_map);

    n = rho_bitmap_size(fdtab->dt_map);
    newp->dt_openmemfiles = rhoL_mallocarray(n, 
            sizeof(struct smuf_memfile *), 0);
    
    RHO_BITMAP_FOREACH(fd, bitval, fdtab->dt_map) {
        if (bitval == 0)
            continue;
        mf = fdtab->dt_openmemfiles[fd];
        mf->f_client_refcnt++;
        newp->dt_openmemfiles[fd] = mf;
    }

    RHO_TRACE_EXIT();
    return (newp);
}

static void
smuf_client_fdtable_destroy(struct smuf_client *client)
{
    struct smuf_desctable *fdtab = client->cli_fdtab;
    size_t fd = 0;
    int bitval = 0;

    RHO_TRACE_ENTER();

    RHO_BITMAP_FOREACH(fd, bitval, fdtab->dt_map) {
        if (bitval == 0)
            continue;
        smuf_memfile_close(client, fd);
    }

    rhoL_free(fdtab->dt_openmemfiles);
    rho_bitmap_destroy(fdtab->dt_map);
    rhoL_free(fdtab);

    RHO_TRACE_EXIT();
    return;
}

/**************************************
 * CLIENT
 **************************************/

static struct smuf_client *
smuf_client_find(uint64_t id)
{
    struct smuf_client *iter = NULL;

    RHO_TRACE_ENTER();

    RHO_LIST_FOREACH(iter, &smuf_clients, cli_next_client) {
        if (iter->cli_id == id)
            goto done;
    }
    iter = NULL;

done:
    RHO_TRACE_EXIT();
    return (iter);
}

static void
smuf_client_add(struct smuf_client *client)
{
    uint64_t id = 0;
    struct smuf_client *iter = NULL;

    RHO_TRACE_ENTER();

    /* find a unique client id */
    do {
again:
        id = rho_rand_u64();
        RHO_LIST_FOREACH(iter, &smuf_clients, cli_next_client) {
            if (iter->cli_id == id)
                goto again;
        }
        break;
    } while (1);

    client->cli_id = id;
    RHO_LIST_INSERT_HEAD(&smuf_clients, client, cli_next_client);

    RHO_TRACE_EXIT();
    return;
}

static struct smuf_client *
smuf_client_alloc(void)
{
    struct smuf_client *client = NULL;

    RHO_TRACE_ENTER();

    client = rhoL_zalloc(sizeof(*client));
    client->cli_agent = rpc_agent_create(NULL, NULL);

    RHO_TRACE_EXIT();
    return (client);
}

static struct smuf_client *
smuf_client_create(struct rho_sock *sock)
{
    struct smuf_client *client = NULL;
    struct rpc_agent *agent = NULL;

    RHO_TRACE_ENTER();

    client = smuf_client_alloc();
    agent = client->cli_agent;
    agent->ra_sock = sock;

    /* has an ssl_ctx */
    if (sock->ssl != NULL)
        agent->ra_state = RPC_STATE_HANDSHAKE;
    else
        agent->ra_state = RPC_STATE_RECV_HDR;

    RHO_TRACE_EXIT();
    return (client);
}

static struct smuf_client *
smuf_client_fork(struct smuf_client *parent)
{
    struct smuf_client *client = NULL;

    RHO_TRACE_ENTER();

    client = smuf_client_alloc();
    client->cli_fdtab = smuf_fdtable_copy(parent->cli_fdtab);

    RHO_TRACE_EXIT();
    return (client);
}

/*
 * a is from the child connecing
 * b is from the parent's fork
 *
 * a gets b's fdtable
 * b is deleted
 */
static void
smuf_client_splice(struct smuf_client *a, struct smuf_client *b)
{
    RHO_TRACE_ENTER();

    a->cli_fdtab = b->cli_fdtab;
    b->cli_fdtab = NULL;

    RHO_LIST_REMOVE(b, cli_next_client);
    smuf_client_destroy(b);

    RHO_TRACE_EXIT();
    return;
};

static void
smuf_client_destroy(struct smuf_client *client)
{
    RHO_ASSERT(client != NULL);

    RHO_TRACE_ENTER("id=0x%"PRIx64, client->cli_id);
    
    rpc_agent_destroy(client->cli_agent);

    if (client->cli_fdtab != NULL)
        smuf_client_fdtable_destroy(client);

    rhoL_free(client);

    RHO_TRACE_EXIT();
}

static void
smuf_client_dispatch_call(struct smuf_client *client)
{
    struct rpc_agent *agent = client->cli_agent;
    uint32_t opcode = agent->ra_hdr.rh_code;
    smuf_opcall opcall = NULL;

    RHO_ASSERT(agent->ra_state == RPC_STATE_DISPATCHABLE);
    RHO_ASSERT(rho_buf_tell(agent->ra_bodybuf) == 0);

    RHO_TRACE_ENTER("fd=%d, opcode=%d", agent->ra_sock->fd, opcode);

    if (opcode >= RHO_C_ARRAY_SIZE(smuf_opcalls)) {
        rho_log_warn(smuf_log, "bad opcode (%"PRIu32")", opcode);
        rpc_agent_new_msg(agent, ENOSYS);
        goto done;
    } 

    if ((client->cli_fdtab == NULL) && 
        ((opcode != SMUF_OP_NEW_FDTABLE) && (opcode != SMUF_OP_CHILD_ATTACH))) {
        rho_log_warn(smuf_log,
                "client attempting file operations without an fdtable");
        rpc_agent_new_msg(agent, EPERM);
        goto done;
    }

    opcall = smuf_opcalls[opcode];
    opcall(client);

done:
    rpc_agent_ready_send(agent);
    RHO_TRACE_EXIT();
    return;
}

static void
smuf_client_cb(struct rho_event *event, int what,
        struct rho_event_loop *loop)
{
    int ret = 0;
    struct smuf_client *client = NULL;
    struct rpc_agent *agent = NULL;

    RHO_ASSERT(event != NULL);
    RHO_ASSERT(event->userdata != NULL);
    RHO_ASSERT(loop != NULL);

    (void)what;

    client = event->userdata;
    agent = client->cli_agent;

    RHO_TRACE_ENTER("fd=%d, what=%08x, state=%s",
            event->fd,
            what,
            rpc_state_to_str(agent->ra_state));
            
    if (agent->ra_state == RPC_STATE_HANDSHAKE) {
        ret = rho_ssl_do_handshake(agent->ra_sock);
        rho_debug("rho_ssl_do_handshake returned %d", ret);
        if (ret == 0) {
            /* ssl handshake complete */
            agent->ra_state  = RPC_STATE_RECV_HDR;
            event->flags = RHO_EVENT_READ;
            goto again;
        } else if (ret == 1) {
            /* ssl handshake still in progress: want_read */
            event->flags = RHO_EVENT_READ;
            goto again;
        } else if (ret == 2) {
            /* ssl handshake still in progress: want_write */
            event->flags = RHO_EVENT_WRITE;
            goto again;
        } else {
            /* an error occurred during the handshake */
            agent->ra_state = RPC_STATE_ERROR; /* not needed */
            goto done;
        }
    }

    if (agent->ra_state == RPC_STATE_RECV_HDR)
        rpc_agent_recv_hdr(agent);

    if (agent->ra_state == RPC_STATE_RECV_BODY)
        rpc_agent_recv_body(agent);

    if (agent->ra_state == RPC_STATE_DISPATCHABLE)
        smuf_client_dispatch_call(client);

    if (agent->ra_state == RPC_STATE_SEND_HDR)
        rpc_agent_send_hdr(agent);

    if (agent->ra_state == RPC_STATE_SEND_BODY)
        rpc_agent_send_body(agent);

    if ((agent->ra_state == RPC_STATE_ERROR) ||
            (agent->ra_state == RPC_STATE_CLOSED)) {
        goto done;
    }

again:
    rho_event_loop_add(loop, event, NULL); 
    RHO_TRACE_EXIT("reschedule callback; state=%s", 
            rpc_state_to_str(agent->ra_state));
    return;

done:
    RHO_LIST_REMOVE(client, cli_next_client);
    rho_log_info(smuf_log, "id=0x%"PRIx64" disconnected", client->cli_id);
    smuf_client_destroy(client);
    RHO_TRACE_EXIT("client done");
    return;
}

/**************************************
 * SERVER
 **************************************/

static struct smuf_server *
smuf_server_alloc(void)
{
    struct smuf_server *server = NULL;
    server = rhoL_zalloc(sizeof(*server));
    return (server);
}

static void
smuf_server_destroy(struct smuf_server *server)
{
    int error = 0;

    if (server->srv_sock != NULL) {
        if (server->srv_udspath[0] != '\0') {
            error = unlink((const char *)server->srv_udspath);
            if (error != 0)
                rho_errno_warn(errno, "unlink('%s') failed", server->srv_udspath);
        }
        rho_sock_destroy(server->srv_sock);
    }

    /* TODO: umount and deregister */

    rhoL_free(server);
}

static void
smuf_server_config_ssl(struct smuf_server *server,
        const char *cafile, const char *certfile, const char *keyfile)
{
    struct rho_ssl_params *params = NULL;
    struct rho_ssl_ctx *sc = NULL;

    RHO_TRACE_ENTER("cafile=%s, certfile=%s, keyfile=%s",
            cafile, certfile, keyfile);

    params = rho_ssl_params_create();
    rho_ssl_params_set_mode(params, RHO_SSL_MODE_SERVER);
    rho_ssl_params_set_protocol(params, RHO_SSL_PROTOCOL_TLSv1_2);
    rho_ssl_params_set_private_key_file(params, keyfile);
    rho_ssl_params_set_certificate_file(params, certfile);
    rho_ssl_params_set_ca_file(params, cafile);
    rho_ssl_params_set_verify(params, false);
    sc = rho_ssl_ctx_create(params);
    server->srv_sc = sc;
    rho_ssl_params_destroy(params);

    RHO_TRACE_EXIT();
}

static void
smuf_server_socket_create(struct smuf_server *server, const char *udspath,
        bool anonymous)
{
    size_t pathlen = 0;
    struct rho_sock *sock = NULL;

    pathlen = strlen(udspath) + 1;
    if (anonymous) {
        strcpy((char *)(server->srv_udspath + 1), udspath);
        pathlen += 1;
    } else {
        strcpy((char *)server->srv_udspath, udspath);
    }
    
    sock = rho_sock_unixserver_create(server->srv_udspath, pathlen, 5);
    rho_sock_setnonblocking(sock);
    server->srv_sock = sock;
}

static void
smuf_server_cb(struct rho_event *event, int what,
        struct rho_event_loop *loop)
{
    int cfd = 0;
    struct sockaddr_un addr;
    socklen_t addrlen = sizeof(addr);
    struct rho_event *cevent = NULL;
    struct smuf_client *client = NULL;
    struct smuf_server *server = NULL;
    struct rho_sock *csock = NULL;

    RHO_ASSERT(event != NULL);
    RHO_ASSERT(loop != NULL);
    RHO_ASSERT(event->userdata != NULL);
    server = event->userdata;

    fprintf(stderr, "server callback (fd=%d, what=%08x)\n", event->fd, what);

    cfd = accept(event->fd, (struct sockaddr *)&addr, &addrlen);
    if (cfd == -1)
        rho_errno_die(errno, "accept failed");
    /* TODO: check that addrlen == sizeof struct soackaddr_un */

    csock = rho_sock_unix_from_fd(cfd);
    rho_sock_setnonblocking(csock);
    if (server->srv_sc != NULL)
        rho_ssl_wrap(csock, server->srv_sc);
    client = smuf_client_create(csock);
    smuf_client_add(client);
    rho_log_info(smuf_log, "new connection: id=0x%"PRIx64, client->cli_id);
    /* XXX: memory leak? -- where do we destroy the event? */
    cevent = rho_event_create(cfd, RHO_EVENT_READ, smuf_client_cb, client);
    client->cli_agent->ra_event = cevent;
    rho_event_loop_add(loop, cevent, NULL); 
}

/**************************************
 * LOG
 **************************************/

static void
smuf_log_init(const char *logfile, bool verbose)
{
    int fd = STDERR_FILENO;

    if (logfile != NULL) {
        fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT,
                S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH,S_IWOTH);
        if (fd == -1)
            rho_errno_die(errno, "can't open or creat logfile \"%s\"", logfile);
    }

    smuf_log = rho_log_create(fd, RHO_LOG_INFO, rho_log_default_writer, NULL);

    if (verbose) 
        rho_log_set_level(smuf_log, RHO_LOG_DEBUG);

    if (logfile != NULL) {
        rho_log_redirect_stderr(smuf_log);
        (void)close(fd);
    }
}

#define SMUFSERVER_USAGE \
    "usage: smuf [options] UDSPATH\n" \
    "\n" \
    "OPTIONS:\n" \
    "   -a\n" \
    "       Treat UDSPATH as an abstract socket\n" \
    "       (adds a leading nul byte to UDSPATH)\n" \
    "\n" \
    "   -d\n" \
    "       Daemonize\n" \
    "\n" \
    "   -h\n" \
    "       Show this help message and exit\n" \
    "\n" \
    "   -l LOG_FILE\n" \
    "       Log file to use.  If not specified, logs are printed to stderr.\n" \
    "       If specified, stderr is also redirected to the log file.\n" \
    "\n" \
    "   -r ROOTDIR\n" \
    "       The directory where the lock and memory files are stored.\n" \
    "       If not specified, the default is the current working directory\n" \
    "\n" \
    "   -v\n" \
    "       Verbose logging.\n" \
    "\n" \
    "   -Z  CACERT CERT PRIVKEY\n" \
    "       Sets the path to the server certificate file and private key\n" \
    "       in PEM format.  This also causes the server to start SSL mode\n" \
    "\n" \
    "\n" \
    "ARGUMENTS:\n" \
    "   UDSPATH\n" \
    "       The path to the UNIX domain socket to listen to connections on\n" \

static void
usage(int exitcode)
{
    fprintf(stderr, "%s\n", SMUFSERVER_USAGE);
    exit(exitcode);
}

int
main(int argc, char *argv[])
{
    int c = 0;
    struct smuf_server *server = NULL;
    struct rho_event *event = NULL;
    struct rho_event_loop *loop = NULL;
    /* options */
    bool anonymous = false;
    bool daemonize  = false;
    const char *logfile = NULL;
    bool verbose = false;

    rho_ssl_init();

    server  = smuf_server_alloc();
    while ((c = getopt(argc, argv, "adhl:r:vZ:")) != -1) {
        switch (c) {
        case 'a':
            anonymous = true;
            break;
        case 'd':
            daemonize = true;
            break;
        case 'h':
            usage(EXIT_SUCCESS);
            break;
        case 'l':
            logfile = optarg;
            break;
        case 'r':
            smuf_root = optarg;
            break;
        case 'v':
            verbose = true;
            break;
        case 'Z':
            /* make sure there's three arguments */
            if ((argc - optind) < 2)
                usage(EXIT_FAILURE);
            smuf_server_config_ssl(server, optarg, argv[optind], argv[optind + 1]);
            optind += 2;
            break;
        default:
            usage(1);
        }
    }
    argc -= optind;
    argv += optind;

    if (argc != 1)
        usage(EXIT_FAILURE);

    if (daemonize)
        rho_daemon_daemonize(NULL, 0);

    smuf_log_init(logfile, verbose);

    smuf_server_socket_create(server, argv[0], anonymous);

    event = rho_event_create(server->srv_sock->fd, RHO_EVENT_READ | RHO_EVENT_PERSIST, 
            smuf_server_cb, server); 

    loop = rho_event_loop_create();
    rho_event_loop_add(loop, event, NULL); 
    rho_event_loop_dispatch(loop);

    /* TODO: destroy event and event_loop */

    smuf_server_destroy(server);
    rho_ssl_fini();

    return (0);
}
