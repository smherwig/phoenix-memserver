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
    void        *f_addr;
    size_t      f_size;
    uint64_t    f_lock_owner_id;
    int         f_refcnt;
    RHO_RB_ENTRY(smdish_memfile) f_memfile;
};

RHO_RB_HEAD(smdish_memfile_tree, smdish_memfile);

struct smdish_fdtable {
    struct rho_bitmap *ft_map;
    /* array of pointers to open memfiles */
    struct smdish_memfile **ft_openfiles;
};

struct smdish_client {
    RHO_LIST_ENTRY(smdish_client) cli_next_client;
    struct rpc_agent        *cli_agent;
    struct smdish_fdtable   *cli_fdtab;
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

static int smdish_memfile_lock(struct smdish_client *client, uint32_t fd,
        struct smdish_memfile **mf_out);

static int smdish_memfile_unlock(struct smdish_client *client, uint32_t fd,
        struct smdish_memfile **mf_out);

static int smdish_memfile_add_map(struct smdish_client *client, uint32_t fd,
        uint32_t size);

static int smdish_memfile_remove_map(struct smdish_client *client,
        uint32_t fd);

/* rpc handlers */
static void smdish_new_fdtable_proxy(struct smdish_client *client);
static void smdish_fork_proxy(struct smdish_client *client);
static void smdish_child_attach_proxy(struct smdish_client *client);
static void smdish_open_proxy(struct smdish_client *client);
static void smdish_close_proxy(struct smdish_client *client);
static void smdish_lock_proxy(struct smdish_client *client);
static void smdish_unlock_proxy(struct smdish_client *client);
static void smdish_mmap_proxy(struct smdish_client *client);
static void smdish_munmap_proxy(struct smdish_client *client);

/* fdtable */
static struct smdish_fdtable * smdish_fdtable_create(void);
static void smdish_fdtable_expand(struct smdish_fdtable *fdtab);

static struct smdish_fdtable * smdish_fdtable_copy(
        const struct smdish_fdtable *fdtab);

static int smdish_fdtable_fdalloc(struct smdish_fdtable *fdtab);

static int smdish_fdtable_setopenfile(struct smdish_fdtable *fdtab,
        struct smdish_memfile *mf);

static struct smdish_memfile * smdish_fdtable_getfile(
        struct smdish_fdtable *fdtab, uint32_t fd);

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

static void smdish_server_socket_create(struct smdish_server *server,
        const char *udspath, bool anonymous);

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
    [SMDISH_OP_MUNMAP]  = smdish_munmap_proxy,
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

    mf->f_refcnt = 1;
    mf->f_lock_owner_id = SMDISH_NO_OWNER;

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
    struct smdish_fdtable *fdtab = client->cli_fdtab;
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    mf = smdish_memfile_tree_find(name);
    if (mf == NULL) {
        mf = smdish_memfile_create(name);
        RHO_RB_INSERT(smdish_memfile_tree, &smdish_memfile_tree_root, mf);
    }
    mf->f_refcnt++;
    *fd = smdish_fdtable_setopenfile(fdtab, mf);

    RHO_TRACE_EXIT();
    return (0);
}

static int
smdish_memfile_close(struct smdish_client *client, uint32_t fd)
{
    int error = 0;
    struct smdish_fdtable *fdtab = client->cli_fdtab;
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    mf = smdish_fdtable_getfile(fdtab, fd);
    if (mf == NULL) {
        error = EBADF;
        goto done;
    }

    if (mf->f_lock_owner_id == client->cli_id)
        mf->f_lock_owner_id = SMDISH_NO_OWNER;

    mf->f_refcnt--;
    if (mf->f_refcnt == 0) {
        RHO_RB_REMOVE(smdish_memfile_tree, &smdish_memfile_tree_root, mf);
        smdish_memfile_destroy(mf);
    }

    rho_bitmap_clear(fdtab->ft_map, fd);

done:
    RHO_TRACE_EXIT();
    return (error);
}

/* 
 * as a convenience, on success, if mf_out is not NULL, return
 * the memfile to the caller.
 */
static int
smdish_memfile_lock(struct smdish_client *client, uint32_t fd,
        struct smdish_memfile **mf_out)
{
    int error = 0;
    struct smdish_fdtable *fdtab = client->cli_fdtab;
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    mf = smdish_fdtable_getfile(fdtab, fd);
    if (mf == NULL) {
        error = EBADF;
        goto fail;
    }

    if (mf->f_lock_owner_id == SMDISH_NO_OWNER) {
        mf->f_lock_owner_id = client->cli_id;
        goto succeed;
    }

    if (mf->f_lock_owner_id == client->cli_id)
        goto succeed;

    error = EAGAIN;
    goto fail;


succeed:
    if (mf_out != NULL)
        *mf_out = mf;
fail:
    RHO_TRACE_EXIT();
    return (error);
}

/* 
 * as a convenience, on success, if mf_out is not NULL, return
 * the memfile to the caller.
 */
static int
smdish_memfile_unlock(struct smdish_client *client, uint32_t fd,
        struct smdish_memfile **mf_out)
{
    int error = 0;
    struct smdish_fdtable *fdtab = client->cli_fdtab;
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    mf = smdish_fdtable_getfile(fdtab, fd);
    if (mf == NULL) {
        error = EBADF;
        goto done;
    }

    if (mf->f_lock_owner_id != client->cli_id) {
        error = EINVAL;
        goto done;
    } else {
        mf->f_lock_owner_id = SMDISH_NO_OWNER;
        if (mf_out != NULL)
            *mf_out = mf;
    }

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
smdish_memfile_add_map(struct smdish_client *client, uint32_t fd,
        uint32_t size)
{
    int error = 0;
    struct smdish_fdtable *fdtab = client->cli_fdtab;
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    mf = smdish_fdtable_getfile(fdtab, fd);
    if (mf == NULL) {
        error = EBADF;
        goto done;
    }

    mf->f_size = size;
    mf->f_addr = rhoL_zalloc(size);

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
smdish_memfile_remove_map(struct smdish_client *client, uint32_t fd)
{
    int error = 0;
    struct smdish_fdtable *fdtab = client->cli_fdtab;
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    mf = smdish_fdtable_getfile(fdtab, fd);
    if (mf == NULL) {
        error = EBADF;
        goto done;
    }

    if (mf->f_addr == NULL) {
        error = EINVAL;
        goto done;
    }

    rhoL_free(mf->f_addr);
    mf->f_addr = NULL;
    mf->f_size = 0;

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

    client->cli_fdtab = smdish_fdtable_create();

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

    error = smdish_memfile_open_or_create(client, name, &fd);

done:
    rpc_agent_new_msg(agent, error);
    if (error) {
        rho_log_errno_debug(smdish_log, error, "id=0x%"PRIx64" open(\"%s\")",
            client->cli_id, name);
    } else {
        rpc_agent_set_bodylen(agent, 4);
        rho_buf_writeu32be(buf, fd);
        rho_log_errno_debug(smdish_log, error, "id=0x%"PRIx64" open(\"%s\") -> %d",
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
    rho_log_errno_debug(smdish_log, error, "id=0x%"PRIx64" close(\"%d\")",
        client->cli_id, fd);

    RHO_TRACE_EXIT();
    return;
}

static void
smdish_lock_proxy(struct smdish_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint32_t fd = 0;
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, &fd);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    error = smdish_memfile_lock(client, fd, &mf);

done:
    rpc_agent_new_msg(agent, error);
    if (!error) {
        /* FIXME: check for integer overflow */
        rpc_agent_set_bodylen(agent, 4 + mf->f_size);
        rho_buf_writeu32be(buf, mf->f_size);
        rho_buf_write(buf, mf->f_addr, mf->f_size);
    }

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
    uint32_t size = 0;
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, &fd);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    error = smdish_memfile_unlock(client, fd, &mf);
    if (error != 0)
        goto done;

    error = rho_buf_readu32be(buf, &size);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    /* 
     * FIXME: check that the read will succeed beforehand; otherwise,
     * mf->addr is left in a corrrupted state on failure
     */
    if (rho_buf_read(buf, mf->f_addr, size) != size) {
        error = EPROTO;
        goto done;
    }

done:
    rpc_agent_new_msg(agent, error);

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
            "id=-x%"PRIx64" mmap(%"PRIu32", %"PRIu32")",
            client->cli_id, fd, size);

    RHO_TRACE_EXIT();
    return;
}

static void
smdish_munmap_proxy(struct smdish_client *client)
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

    error = smdish_memfile_remove_map(client, fd);

done:
    rpc_agent_new_msg(agent, error);
    RHO_TRACE_EXIT();
    return;
}

/**************************************
 * FDTABLE
 **************************************/

static struct smdish_fdtable *
smdish_fdtable_create(void)
{
    struct smdish_fdtable *fdtab = NULL;

    RHO_TRACE_ENTER();

    fdtab = rhoL_zalloc(sizeof(*fdtab));
    fdtab->ft_map = rho_bitmap_create(true, 20);
    fdtab->ft_openfiles = rhoL_mallocarray(20, sizeof(struct smdish_memfile *), 0);

    RHO_TRACE_EXIT();
    return (fdtab);
}

static void
smdish_fdtable_expand(struct smdish_fdtable *fdtab)
{
    size_t newmaxbits = 0;
    struct rho_bitmap *map = fdtab->ft_map;

    RHO_TRACE_ENTER();
    
    /* TODO: check for overflow; also, check that this actually
     * expands, since the range of size_t is greater than int
     */
    newmaxbits = rho_bitmap_size(map) + 32;
    rho_bitmap_resize(map, newmaxbits);
    fdtab->ft_openfiles = rhoL_reallocarray(fdtab->ft_openfiles,
            newmaxbits, sizeof(struct smdish_memfile *), 0);

    RHO_TRACE_EXIT();
}

static struct smdish_fdtable *
smdish_fdtable_copy(const struct smdish_fdtable *fdtab)
{
    struct smdish_fdtable *newp = NULL;
    struct smdish_memfile *mf = NULL;
    size_t fd = 0;
    int bitval = 0;
    size_t n = 0;

    RHO_TRACE_ENTER();

    newp = rhoL_zalloc(sizeof(*newp));
    newp->ft_map = rho_bitmap_copy(fdtab->ft_map);

    n = rho_bitmap_size(fdtab->ft_map);
    newp->ft_openfiles = rhoL_mallocarray(n, sizeof(struct smdish_memfile *), 0);
    
    RHO_BITMAP_FOREACH(fd, bitval, fdtab->ft_map) {
        if (bitval == 0)
            continue;
        mf = fdtab->ft_openfiles[fd];
        mf->f_refcnt++;
        newp->ft_openfiles[fd] = mf;
    }

    RHO_TRACE_EXIT();
    return (newp);
}

static int
smdish_fdtable_fdalloc(struct smdish_fdtable *fdtab)
{
    int fd = 0;
    size_t oldmaxbits = 0;
    struct rho_bitmap *map = fdtab->ft_map;

    RHO_TRACE_ENTER();

    /* TODO: you might want some upper limit on how many files a client can
     * have open
     */
    fd = rho_bitmap_ffc(map);
    if (fd == -1) {
        oldmaxbits = rho_bitmap_size(map);
        smdish_fdtable_expand(fdtab);
        fd = oldmaxbits;
    }

    rho_bitmap_set(fdtab->ft_map, fd);

    RHO_TRACE_EXIT("fd=%d", fd);
    return (fd);
}

static int
smdish_fdtable_setopenfile(struct smdish_fdtable *fdtab,
        struct smdish_memfile *mf)
{
    int fd = 0;

    RHO_TRACE_ENTER();

    fd = smdish_fdtable_fdalloc(fdtab);
    fdtab->ft_openfiles[fd] = mf;

    RHO_TRACE_EXIT("fd=%d", fd);
    return (fd);
}

static struct smdish_memfile *
smdish_fdtable_getfile(struct smdish_fdtable *fdtab, uint32_t fd)
{
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    if (!rho_bitmap_isset(fdtab->ft_map, fd))
        goto done;

    mf = fdtab->ft_openfiles[fd];
    RHO_ASSERT(mf != NULL);

done:
    RHO_TRACE_EXIT();
    return (mf);
}

static void
smdish_client_fdtable_destroy(struct smdish_client *client)
{
    struct smdish_fdtable *fdtab = client->cli_fdtab;
    size_t fd = 0;
    int bitval = 0;

    RHO_TRACE_ENTER();

    RHO_BITMAP_FOREACH(fd, bitval, fdtab->ft_map) {
        if (bitval == 0)
            continue;
        smdish_memfile_close(client, fd);
    }

    rhoL_free(fdtab->ft_openfiles);
    rho_bitmap_destroy(fdtab->ft_map);
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
smdish_server_socket_create(struct smdish_server *server, const char *udspath,
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

    csock = rho_sock_unix_from_fd(cfd);
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
    "usage: smdish [options] UDSPATH\n" \
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
    bool anonymous = false;
    bool daemonize  = false;
    const char *logfile = NULL;
    bool verbose = false;

    rho_ssl_init();

    server  = smdish_server_alloc();
    while ((c = getopt(argc, argv, "adhl:vZ:")) != -1) {
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

    if (argc != 1)
        usage(EXIT_FAILURE);

    if (daemonize)
        rho_daemon_daemonize(NULL, 0);

    smdish_log_init(logfile, verbose);

    smdish_server_socket_create(server, argv[0], anonymous);

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
