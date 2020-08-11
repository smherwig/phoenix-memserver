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

#include "smdish.h"

/**************************************
 * TYPES
 **************************************/
struct smdish_server {
    struct rho_sock *srv_sock;
    struct rho_ssl_ctx *srv_sc;
    /* TODO: don't hardcode 108 */
    uint8_t srv_udspath[108];
};

struct smdish_memfile {
    char        f_name[SMDISH_MAX_NAME_SIZE];
    int         f_client_refcnt;    /* #clients that are using this file */
    uint64_t    f_lock_owner_id;

    uint8_t     f_type;

    void        *f_addr;
    size_t      f_map_size;

    RHO_RB_ENTRY(smdish_memfile) f_memfile;
};

RHO_RB_HEAD(smdish_memfile_tree, smdish_memfile);

struct smdish_desctable {
    struct rho_bitmap *dt_map;
    /* array of pointers to open memfiles */
    struct smdish_memfile **dt_openmemfiles;
};

struct smdish_client {
    RHO_LIST_ENTRY(smdish_client) cli_next_client;
    struct rpc_agent        *cli_agent;
    struct smdish_desctable *cli_fdtab;
    uint64_t                cli_id;
};

RHO_LIST_HEAD(smdish_client_list, smdish_client);

typedef void (*smdish_opcall)(struct smdish_client *client);

/**************************************
 * FORWARD DECLARATIONS
 **************************************/

/* memfile tree */
static int smdish_memfile_cmp(struct smdish_memfile *a,
        struct smdish_memfile *b);

static struct smdish_memfile * smdish_memfile_tree_find(const char *name);
static struct smdish_memfile * smdish_memfile_create(const char *name);

/* memfile */
static void smdish_memfile_destroy(struct smdish_memfile *mf);

static int smdish_memfile_open_or_create(struct smdish_client *client,
        const char *name, uint32_t *fd);

static int smdish_memfile_close(struct smdish_client *client, uint32_t fd);

static int smdish_memfile_add_map(struct smdish_client *client, uint32_t fd,
        uint32_t map_size);

/* rpc handlers */
static void smdish_new_fdtable_proxy(struct smdish_client *client);
static void smdish_fork_proxy(struct smdish_client *client);
static void smdish_child_attach_proxy(struct smdish_client *client);
static void smdish_open_proxy(struct smdish_client *client);
static void smdish_close_proxy(struct smdish_client *client);
static void smdish_lock_proxy(struct smdish_client *client);
static void smdish_unlock_proxy(struct smdish_client *client);
static void smdish_mmap_proxy(struct smdish_client *client);

/* desctable */
static struct smdish_desctable * smdish_desctable_create(void);
static void smdish_desctable_expand(struct smdish_desctable *tab);
static int smdish_desctable_descalloc(struct smdish_desctable *tab);
static int smdish_desctable_setopenmemfile(struct smdish_desctable *tab,
        struct smdish_memfile *mf);

static struct smdish_memfile * smdish_desctable_getmemfile(
        struct smdish_desctable *tab, uint32_t fd);

/* 
 * desctable: specific functions locks files (fdtable)
 */
static struct smdish_desctable * smdish_fdtable_copy(
        const struct smdish_desctable *fdtab);

static void smdish_client_fdtable_destroy(struct smdish_client *client);

/* client */
static struct smdish_client * smdish_client_find(uint64_t id);
static void smdish_client_add(struct smdish_client *client);
static struct smdish_client * smdish_client_alloc(void);
static struct smdish_client * smdish_client_create(struct rho_sock *sock);
static struct smdish_client * smdish_client_fork(struct smdish_client *parent);

static void smdish_client_splice(struct smdish_client *a, 
        struct smdish_client *b);

static void smdish_client_destroy(struct smdish_client *client);
static void smdish_client_dispatch_call(struct smdish_client *client);

static void smdish_client_cb(struct rho_event *event, int what,
        struct rho_event_loop *loop);

/* server */
static struct smdish_server * smdish_server_alloc(void);
static void smdish_server_destroy(struct smdish_server *server);

static void smdish_server_config_ssl(struct smdish_server *server,
        const char *cafile, const char *certfile, const char *keyfile);

static void smdish_server_unix_socket_create(struct smdish_server *server,
        const char *udspath, bool anonymous);

static void smdish_server_tcp4_socket_create(struct smdish_server *server,
        short port);

static void smdish_server_cb(struct rho_event *event, int what,
        struct rho_event_loop *loop);

/* log */
static void smdish_log_init(const char *logfile, bool verbose);

/* usage */
static void
usage(int exitcode);

/**************************************
 * GLOBALS
 **************************************/

struct rho_log *smdish_log = NULL;

struct smdish_memfile_tree smdish_memfile_tree_root = 
        RHO_RB_INITIALIZER(&smdish_memfile_tree_root);

static struct smdish_client_list smdish_clients =
        RHO_LIST_HEAD_INITIALIZER(smdish_clients);

static smdish_opcall smdish_opcalls[] = {
    [SMDISH_OP_NEW_FDTABLE]  = smdish_new_fdtable_proxy,
    [SMDISH_OP_FORK]         = smdish_fork_proxy,
    [SMDISH_OP_CHILD_ATTACH] = smdish_child_attach_proxy,

    [SMDISH_OP_OPEN]    = smdish_open_proxy,
    [SMDISH_OP_CLOSE]   = smdish_close_proxy,
    [SMDISH_OP_MMAP]    = smdish_mmap_proxy,
    [SMDISH_OP_LOCK]    = smdish_lock_proxy,
    [SMDISH_OP_UNLOCK]  = smdish_unlock_proxy,
};

/**************************************
 * RED-BLACK TREE OF MEMFILES
 **************************************/

static int
smdish_memfile_cmp(struct smdish_memfile *a, struct smdish_memfile *b)
{
    return (strcmp(a->f_name, b->f_name));
}

RHO_RB_GENERATE_STATIC(smdish_memfile_tree, smdish_memfile, f_memfile,
        smdish_memfile_cmp);

static struct smdish_memfile *
smdish_memfile_tree_find(const char *name)
{
    size_t n = 0;
    struct smdish_memfile key;
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    n = rho_strlcpy(key.f_name, name, SMDISH_MAX_NAME_SIZE);
    if (n >= SMDISH_MAX_NAME_SIZE) {
        rho_warn("strlcpy truncation would occur\n");
        goto done;
    }

    mf = RHO_RB_FIND(smdish_memfile_tree, &smdish_memfile_tree_root, &key);

done:
    RHO_TRACE_EXIT();
    return (mf);
}

/**************************************
 * MEMFILE
 **************************************/

static struct smdish_memfile *
smdish_memfile_create(const char *name)
{
    size_t n = 0;
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    mf = rhoL_zalloc(sizeof(*mf));

    n = rho_strlcpy(mf->f_name, name, sizeof(mf->f_name));
    RHO_ASSERT(n < sizeof(mf->f_name));

    mf->f_client_refcnt = 1;
    mf->f_lock_owner_id = SMDISH_NO_OWNER;
    mf->f_type = SMDISH_TYPE_PURE_LOCK;

    RHO_TRACE_EXIT();
    return (mf);
}

static void
smdish_memfile_destroy(struct smdish_memfile *mf)
{
    RHO_TRACE_ENTER();

    if (mf->f_addr != NULL)
        rhoL_free(mf->f_addr);

    rhoL_free(mf);

    RHO_TRACE_EXIT();
    return;
}

static int
smdish_memfile_open_or_create(struct smdish_client *client, const char *name,
        uint32_t *fd)
{
    struct smdish_desctable *fdtab = client->cli_fdtab;
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    mf = smdish_memfile_tree_find(name);
    if (mf == NULL) {
        rho_debug("creating new file \"%s\"", name);
        mf = smdish_memfile_create(name);
        RHO_RB_INSERT(smdish_memfile_tree, &smdish_memfile_tree_root, mf);
    } else {
        rho_debug("opening existing file \"%s\"", name);
        mf->f_client_refcnt++;
    }

    *fd = smdish_desctable_setopenmemfile(fdtab, mf);

    RHO_TRACE_EXIT();
    return (0);
}

static int
smdish_memfile_close(struct smdish_client *client, uint32_t fd)
{
    int error = 0;
    struct smdish_desctable *fdtab = client->cli_fdtab;
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    mf = smdish_desctable_getmemfile(fdtab, fd);
    if (mf == NULL) {
        error = EBADF;
        goto done;
    }

    if (mf->f_lock_owner_id == client->cli_id)
        mf->f_lock_owner_id = SMDISH_NO_OWNER;

    mf->f_client_refcnt--;
    rho_debug("mf->f_client_refcnt=%d", mf->f_client_refcnt);
    if (mf->f_client_refcnt == 0) {
        RHO_RB_REMOVE(smdish_memfile_tree, &smdish_memfile_tree_root, mf);
        smdish_memfile_destroy(mf);
    }

    rho_bitmap_clear(fdtab->dt_map, fd);

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
smdish_memfile_add_map(struct smdish_client *client, uint32_t fd,
        uint32_t map_size)
{
    int error = 0;
    struct smdish_desctable *fdtab = client->cli_fdtab;
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER("fd=%"PRIu32", map_size=%"PRIu32, fd, map_size);

    mf = smdish_desctable_getmemfile(fdtab, fd);
    if (mf == NULL) {
        error = EBADF;
        goto done;
    }

    /* XXX: what should we do if f_addr is not NULL? */
    if (mf->f_addr == NULL) {
        mf->f_map_size = map_size;
        mf->f_addr = rhoL_zalloc(map_size);
        mf->f_type = SMDISH_TYPE_LOCK_WITH_UNINIT_SEGMENT;
    }

done:
    RHO_TRACE_EXIT();
    return (error);
}

/**************************************
 * RPC HANDLERS
 **************************************/

static void
smdish_new_fdtable_proxy(struct smdish_client *client)
{
    struct rpc_agent *agent = client->cli_agent;

    RHO_TRACE_ENTER();

    if (client->cli_fdtab != NULL)
        smdish_client_fdtable_destroy(client);

    client->cli_fdtab = smdish_desctable_create();

    rpc_agent_new_msg(agent, 0);

    rho_log_errno_debug(smdish_log, 0, "id=0x%"PRIx64" new_fdtable()",
        client->cli_id);

    RHO_TRACE_EXIT();
    return;
}

static void
smdish_fork_proxy(struct smdish_client *client)
{
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct smdish_client *child = NULL;
    uint64_t id = 0;

    RHO_TRACE_ENTER();

    child = smdish_client_fork(client);
    smdish_client_add(child);
    id = child->cli_id;

    rpc_agent_new_msg(agent, 0);
    rpc_agent_set_bodylen(agent, 8);
    rho_buf_writeu64be(buf, id);

    rho_log_errno_debug(smdish_log, 0, "id=0x%"PRIx64" fork() -> 0x%"PRIx64,
        client->cli_id, id);

    RHO_TRACE_EXIT();
    return;
}

static void
smdish_child_attach_proxy(struct smdish_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint64_t id;
    struct smdish_client *attachee = NULL;;

    RHO_TRACE_ENTER();

    error = rho_buf_readu64be(buf, &id);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    attachee = smdish_client_find(id);
    if (attachee == NULL) {
        rho_log_warn(smdish_log, "cannot find id=0x%"PRIx64" to attach to", id);
        error = EINVAL;
        goto done;
    }

    smdish_client_splice(client, attachee);
    
done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(smdish_log, error, "id=0x%"PRIx64" child_attach()",
        client->cli_id);

    RHO_TRACE_EXIT();
    return;
}

static void
smdish_open_proxy(struct smdish_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char name[SMDISH_MAX_NAME_SIZE] = { 0 };
    uint32_t name_size = 0;
    uint32_t fd = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, &name_size);
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    if (name_size >= SMDISH_MAX_NAME_SIZE) {
        error = ENAMETOOLONG;
        goto done;
    }

    if (rho_buf_read(buf, name, name_size) != name_size) {
        error = EPROTO;
        goto done;
    }

    error = smdish_memfile_open_or_create(client, name, &fd);

done:
    rpc_agent_new_msg(agent, error);
    if (error) {
        rho_log_errno_debug(smdish_log, error, "id=0x%"PRIx64" open(\"%s\")",
            client->cli_id, name);
    } else {
        rpc_agent_set_bodylen(agent, 4);
        rho_buf_writeu32be(buf, fd);
        rho_log_errno_debug(smdish_log, error,
                "id=0x%"PRIx64" open(\"%s\") -> %d",
                client->cli_id, name, fd);
    }
    RHO_TRACE_EXIT();
    return;
}

static void
smdish_close_proxy(struct smdish_client *client)
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

    error = smdish_memfile_close(client, fd);

done:
    rpc_agent_new_msg(agent, error);
    rho_log_errno_debug(smdish_log, error, "id=0x%"PRIx64" close(%d)",
        client->cli_id, fd);

    RHO_TRACE_EXIT();
    return;
}

static bool
smdish_valid_client_type(uint8_t type)
{
    return ((type == SMDISH_TYPE_PURE_LOCK) || (type == SMDISH_TYPE_LOCK_WITH_SEGMENT));

}

static bool
smdish_memfile_client_type_compatible(const struct smdish_memfile *mf,
        uint8_t type)
{
    return (
            (mf->f_type == type) || 
            
            ((mf->f_type == SMDISH_TYPE_LOCK_WITH_UNINIT_SEGMENT) && 
             (type == SMDISH_TYPE_LOCK_WITH_SEGMENT))
           );
}

static void
smdish_lock_proxy(struct smdish_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint32_t fd = 0;
    uint8_t type = 0;
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, &fd);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_readu8(buf, &type);
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    if (!smdish_valid_client_type(type)) {
        error = EBADE;
        goto done;
    }

    mf = smdish_desctable_getmemfile(client->cli_fdtab, fd);
    if (mf == NULL) {
        error = EBADF;
        goto done;
    }

    if (!smdish_memfile_client_type_compatible(mf, type)) {
        error = EBADE;
        goto done;
    }

    if (mf->f_lock_owner_id == SMDISH_NO_OWNER) {
        mf->f_lock_owner_id = client->cli_id;
        goto done;
    }

    if (mf->f_lock_owner_id == client->cli_id)
        goto done;

    error = EAGAIN;

done:
    rpc_agent_new_msg(agent, error);
    if (!error) {
        rho_buf_writeu8(buf, mf->f_type);
        if (mf->f_type == SMDISH_TYPE_LOCK_WITH_SEGMENT) {
            rho_buf_writeu32be(buf, mf->f_map_size);
            rho_buf_write(buf, mf->f_addr, mf->f_map_size);
        }
        rpc_agent_autoset_bodylen(agent);
    }

    rho_log_errno_debug(smdish_log, error, 
            "id=0x%"PRIx64" lock(%"PRIu32")", client->cli_id, fd);

    RHO_TRACE_EXIT();
    return;
}

static void
smdish_unlock_proxy(struct smdish_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint32_t fd = 0;
    uint8_t type = 0;
    uint32_t map_size = 0;
    struct smdish_memfile *mf = NULL;

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

    if (!smdish_valid_client_type(type)) {
        error = EBADE;
        goto done;
    }

    mf = smdish_desctable_getmemfile(client->cli_fdtab, fd);
    if (mf == NULL) {
        error = EBADF;
        goto done;
    }

    if (!smdish_memfile_client_type_compatible(mf, type)) {
        error = EBADE;
        goto done;
    }

    if (mf->f_lock_owner_id != client->cli_id) {
        error = EINVAL;
        goto done;
    } else {
        mf->f_lock_owner_id = SMDISH_NO_OWNER;
    }

    if (mf->f_type == SMDISH_TYPE_PURE_LOCK)
        goto done;

    rho_debug("fd has associated memory");
    RHO_ASSERT(mf->f_addr != NULL);

    error = rho_buf_readu32be(buf, &map_size);
    if (error == -1) {
        rho_warn("rho_buf_read failed");
        error = EPROTO;
        goto done;
    }

    if (map_size != mf->f_map_size) {
        error = EINVAL;
        goto done;
    }

    if (rho_buf_left(buf) != map_size) {
        error = EPROTO;
        goto done;
    }

    //rho_hexdump(mf->f_addr, 32, "memory before unlock");

    if (rho_buf_read(buf, mf->f_addr, map_size) != map_size) {
        rho_warn("rho_buf_read failed");
        error = EPROTO;
        goto done;
    }

    mf->f_type = SMDISH_TYPE_LOCK_WITH_SEGMENT;
    error = 0;

    //rho_hexdump(mf->f_addr, 32, "memory after unlock");

done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(smdish_log, error, 
            "id=0x%"PRIx64" unlock(%"PRIu32")", client->cli_id, fd);

    RHO_TRACE_EXIT();
    return;
}

static void
smdish_mmap_proxy(struct smdish_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint32_t fd = 0;
    uint32_t size = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, &fd);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    error = rho_buf_readu32be(buf, &size);        
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    error = smdish_memfile_add_map(client, fd, size);

done:
    rpc_agent_new_msg(agent, error);
    rho_log_errno_debug(smdish_log, error, 
                "id=0x%"PRIx64" mmap(%"PRIu32", %"PRIu32")",
                client->cli_id, fd, size);

    RHO_TRACE_EXIT();
    return;
}

/**************************************
 * DESCTABLE
 **************************************/

static struct smdish_desctable *
smdish_desctable_create(void)
{
    struct smdish_desctable *tab = NULL;

    RHO_TRACE_ENTER();

    tab = rhoL_zalloc(sizeof(*tab));
    tab->dt_map = rho_bitmap_create(true, 20);
    tab->dt_openmemfiles = rhoL_mallocarray(20,
            sizeof(struct smdish_memfile *), 0);

    RHO_TRACE_EXIT();
    return (tab);
}

static void
smdish_desctable_expand(struct smdish_desctable *tab)
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
            newmaxbits, sizeof(struct smdish_memfile *), 0);

    RHO_TRACE_EXIT();
}

static int
smdish_desctable_descalloc(struct smdish_desctable *tab)
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
        smdish_desctable_expand(tab);
        d = oldmaxbits;
    }

    rho_bitmap_set(tab->dt_map, d);

    RHO_TRACE_EXIT("d=%d", d);
    return (d);
}

static int
smdish_desctable_setopenmemfile(struct smdish_desctable *tab,
        struct smdish_memfile *mf)
{
    int d = 0;

    RHO_TRACE_ENTER();

    d = smdish_desctable_descalloc(tab);
    tab->dt_openmemfiles[d] = mf;

    RHO_TRACE_EXIT("d=%d", d);
    return (d);
}

static struct smdish_memfile *
smdish_desctable_getmemfile(struct smdish_desctable *tab, uint32_t d)
{
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    if (!rho_bitmap_isset(tab->dt_map, d))
        goto done;

    mf = tab->dt_openmemfiles[d];
    RHO_ASSERT(mf != NULL);

done:
    RHO_TRACE_EXIT();
    return (mf);
}

static struct smdish_desctable *
smdish_fdtable_copy(const struct smdish_desctable *fdtab)
{
    struct smdish_desctable *newp = NULL;
    struct smdish_memfile *mf = NULL;
    size_t fd = 0;
    int bitval = 0;
    size_t n = 0;

    RHO_TRACE_ENTER();

    newp = rhoL_zalloc(sizeof(*newp));
    newp->dt_map = rho_bitmap_copy(fdtab->dt_map);

    n = rho_bitmap_size(fdtab->dt_map);
    newp->dt_openmemfiles = rhoL_mallocarray(n, 
            sizeof(struct smdish_memfile *), 0);
    
    for (fd = 0; fd < n; fd++) {
        bitval = rho_bitmap_get(fdtab->dt_map, fd);
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
smdish_client_fdtable_destroy(struct smdish_client *client)
{
    struct smdish_desctable *fdtab = client->cli_fdtab;
    size_t fd = 0;
    int bitval = 0;

    RHO_TRACE_ENTER();

    for (fd = 0; fd < rho_bitmap_size(fdtab->dt_map); fd++) {
        bitval = rho_bitmap_get(fdtab->dt_map, fd);
        if (bitval == 0)
            continue;
        smdish_memfile_close(client, fd);
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

static struct smdish_client *
smdish_client_find(uint64_t id)
{
    struct smdish_client *iter = NULL;

    RHO_TRACE_ENTER();

    RHO_LIST_FOREACH(iter, &smdish_clients, cli_next_client) {
        if (iter->cli_id == id)
            goto done;
    }
    iter = NULL;

done:
    RHO_TRACE_EXIT();
    return (iter);
}

static void
smdish_client_add(struct smdish_client *client)
{
    uint64_t id = 0;
    struct smdish_client *iter = NULL;

    RHO_TRACE_ENTER();

    /* find a unique client id */
    do {
again:
        id = rho_rand_u64();
        RHO_LIST_FOREACH(iter, &smdish_clients, cli_next_client) {
            if (iter->cli_id == id)
                goto again;
        }
        break;
    } while (1);

    client->cli_id = id;
    RHO_LIST_INSERT_HEAD(&smdish_clients, client, cli_next_client);

    RHO_TRACE_EXIT();
    return;
}

static struct smdish_client *
smdish_client_alloc(void)
{
    struct smdish_client *client = NULL;

    RHO_TRACE_ENTER();

    client = rhoL_zalloc(sizeof(*client));
    client->cli_agent = rpc_agent_create(NULL, NULL);

    RHO_TRACE_EXIT();
    return (client);
}

static struct smdish_client *
smdish_client_create(struct rho_sock *sock)
{
    struct smdish_client *client = NULL;
    struct rpc_agent *agent = NULL;

    RHO_TRACE_ENTER();

    client = smdish_client_alloc();
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

static struct smdish_client *
smdish_client_fork(struct smdish_client *parent)
{
    struct smdish_client *client = NULL;

    RHO_TRACE_ENTER();

    client = smdish_client_alloc();
    client->cli_fdtab = smdish_fdtable_copy(parent->cli_fdtab);

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
smdish_client_splice(struct smdish_client *a, struct smdish_client *b)
{
    RHO_TRACE_ENTER();

    a->cli_fdtab = b->cli_fdtab;
    b->cli_fdtab = NULL;

    RHO_LIST_REMOVE(b, cli_next_client);
    smdish_client_destroy(b);

    RHO_TRACE_EXIT();
    return;
};

static void
smdish_client_destroy(struct smdish_client *client)
{
    RHO_ASSERT(client != NULL);

    RHO_TRACE_ENTER("id=0x%"PRIx64, client->cli_id);
    
    rpc_agent_destroy(client->cli_agent);

    if (client->cli_fdtab != NULL)
        smdish_client_fdtable_destroy(client);

    rhoL_free(client);

    RHO_TRACE_EXIT();
}

static void
smdish_client_dispatch_call(struct smdish_client *client)
{
    struct rpc_agent *agent = client->cli_agent;
    uint32_t opcode = agent->ra_hdr.rh_code;
    smdish_opcall opcall = NULL;

    RHO_ASSERT(agent->ra_state == RPC_STATE_DISPATCHABLE);
    RHO_ASSERT(rho_buf_tell(agent->ra_bodybuf) == 0);

    RHO_TRACE_ENTER("fd=%d, opcode=%d", agent->ra_sock->fd, opcode);

    if (opcode >= RHO_C_ARRAY_SIZE(smdish_opcalls)) {
        rho_log_warn(smdish_log, "bad opcode (%"PRIu32")", opcode);
        rpc_agent_new_msg(agent, ENOSYS);
        goto done;
    } 

    if ((client->cli_fdtab == NULL) && 
        ((opcode != SMDISH_OP_NEW_FDTABLE) && (opcode != SMDISH_OP_CHILD_ATTACH))) {
        rho_log_warn(smdish_log,
                "client attempting file operations without an fdtable");
        rpc_agent_new_msg(agent, EPERM);
        goto done;
    }

    opcall = smdish_opcalls[opcode];
    opcall(client);

done:
    rpc_agent_ready_send(agent);
    RHO_TRACE_EXIT();
    return;
}

static void
smdish_client_cb(struct rho_event *event, int what,
        struct rho_event_loop *loop)
{
    int ret = 0;
    struct smdish_client *client = NULL;
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
        smdish_client_dispatch_call(client);

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
    rho_log_info(smdish_log, "id=0x%"PRIx64" disconnected", client->cli_id);
    smdish_client_destroy(client);
    RHO_TRACE_EXIT("client done");
    return;
}

/**************************************
 * SERVER
 **************************************/

static struct smdish_server *
smdish_server_alloc(void)
{
    struct smdish_server *server = NULL;
    server = rhoL_zalloc(sizeof(*server));
    return (server);
}

static void
smdish_server_destroy(struct smdish_server *server)
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
smdish_server_config_ssl(struct smdish_server *server,
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
smdish_server_unix_socket_create(struct smdish_server *server, const char *udspath,
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
smdish_server_tcp4_socket_create(struct smdish_server *server, short port)
{
    struct rho_sock *sock = NULL; 
    
    sock = rho_sock_tcp4server_create(NULL, port, 5);
    rho_sock_setnonblocking(sock);
    rhoL_setsockopt_disable_nagle(sock->fd);
    server->srv_sock = sock;
}

static void
smdish_server_cb(struct rho_event *event, int what,
        struct rho_event_loop *loop)
{
    int cfd = 0;
    struct sockaddr_un addr;
    socklen_t addrlen = sizeof(addr);
    struct rho_event *cevent = NULL;
    struct smdish_client *client = NULL;
    struct smdish_server *server = NULL;
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

    if (server->srv_sock->af == AF_UNIX) {
        csock = rho_sock_unix_from_fd(cfd);
    } else {
        /* TCP */
        rhoL_setsockopt_disable_nagle(cfd);
        csock = rho_sock_tcp_from_fd(cfd);
    }
    rho_sock_setnonblocking(csock);
    if (server->srv_sc != NULL)
        rho_ssl_wrap(csock, server->srv_sc);
    client = smdish_client_create(csock);
    smdish_client_add(client);
    rho_log_info(smdish_log, "new connection: id=0x%"PRIx64, client->cli_id);
    /* XXX: memory leak? -- where do we destroy the event? */
    cevent = rho_event_create(cfd, RHO_EVENT_READ, smdish_client_cb, client);
    client->cli_agent->ra_event = cevent;
    rho_event_loop_add(loop, cevent, NULL); 
}

/**************************************
 * LOG
 **************************************/

static void
smdish_log_init(const char *logfile, bool verbose)
{
    int fd = STDERR_FILENO;

    if (logfile != NULL) {
        fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT,
                S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH,S_IWOTH);
        if (fd == -1)
            rho_errno_die(errno, "can't open or creat logfile \"%s\"", logfile);
    }

    smdish_log = rho_log_create(fd, RHO_LOG_INFO, rho_log_default_writer, NULL);

    if (verbose) 
        rho_log_set_level(smdish_log, RHO_LOG_DEBUG);

    if (logfile != NULL) {
        rho_log_redirect_stderr(smdish_log);
        (void)close(fd);
    }
}

#define SMDISHSERVER_USAGE \
    "usage: smdish [options]\n" \
    "\n" \
    "OPTIONS:\n" \
    "\n" \
    " One of -p or -u must be specified.\n" \
    "\n" \
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
    "   -p PORT\n" \
    "       Server should listen on TCP address *:PORT \n" \
    "\n" \
    "   -u UNIX_DOMAIN_SOCKET_PATH\n" \
    "       Server should listen on the specified UNIX domain socket.  See\n" \
    "       also the -a flag.\n" \
    "\n" \
    "   -v\n" \
    "       Verbose logging.\n" \
    "\n" \
    "   -Z  CACERT CERT PRIVKEY\n" \
    "       Sets the path to the server certificate file and private key\n" \
    "       in PEM format.  This also causes the server to start SSL mode\n"

static void
usage(int exitcode)
{
    fprintf(stderr, "%s\n", SMDISHSERVER_USAGE);
    exit(exitcode);
}

int
main(int argc, char *argv[])
{
    int c = 0;
    struct smdish_server *server = NULL;
    struct rho_event *event = NULL;
    struct rho_event_loop *loop = NULL;
    /* options */
    bool addr_tcp4 = false;
    short port;
    bool addr_unix = false;
    bool anonymous = false;
    const char *udspath = NULL;
    bool daemonize  = false;
    const char *logfile = NULL;
    bool verbose = false;

    rho_ssl_init();

    server  = smdish_server_alloc();
    while ((c = getopt(argc, argv, "adhl:p:u:vZ:")) != -1) {
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
        case 'p':
            port = rho_str_toshort(optarg, 10);
            addr_tcp4 = true;
            break;
        case 'u':
            udspath = optarg;
            addr_unix = true;
            break;
        case 'v':
            verbose = true;
            break;
        case 'Z':
            /* make sure there's three arguments */
            if ((argc - optind) < 2)
                usage(EXIT_FAILURE);
            smdish_server_config_ssl(server, optarg, argv[optind], argv[optind + 1]);
            optind += 2;
            break;
        default:
            usage(1);
        }
    }
    argc -= optind;
    argv += optind;

    if (argc != 0)
        usage(EXIT_FAILURE);

    if (!addr_unix && !addr_tcp4) {
        fprintf(stderr, "must specifiy either -p or -u\n");
        exit(EXIT_FAILURE);
    }

    if (addr_unix && addr_tcp4) {
        fprintf(stderr, "must specifiy one of -p or -u, not both\n");
        exit(EXIT_FAILURE);
    }

    if (addr_tcp4 && anonymous) {
        fprintf(stderr, "cannot speicfy -p and -a together\n");
        exit(EXIT_FAILURE);
    }

    if (daemonize)
        rho_daemon_daemonize(NULL, 0);

    smdish_log_init(logfile, verbose);

    if (addr_unix) 
        smdish_server_unix_socket_create(server, udspath, anonymous);
    else
        smdish_server_tcp4_socket_create(server, port);


    event = rho_event_create(server->srv_sock->fd, RHO_EVENT_READ | RHO_EVENT_PERSIST, 
            smdish_server_cb, server); 

    loop = rho_event_loop_create();
    rho_event_loop_add(loop, event, NULL); 
    rho_event_loop_dispatch(loop);

    /* TODO: destroy event and event_loop */

    smdish_server_destroy(server);
    rho_ssl_fini();

    return (0);
}
