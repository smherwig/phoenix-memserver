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

#include "mdish.h"

/**************************************
 * TYPES
 **************************************/
struct mdish_server {
    struct rho_sock *srv_sock;
    struct rho_ssl_ctx *srv_sc;
    /* TODO: don't hardcode 108 */
    uint8_t srv_udspath[108];
};

struct mdish_segment {
    RHO_LIST_ENTRY(mdish_segment) seg_next_segment;
    char        *s_name;
    void        *s_addr;
    size_t      s_size;
    int         s_refcnt;
    bool        s_modified;
};

RHO_LIST_HEAD(mdish_segment_list, mdish_segment);

struct mdish_sdtable {
    struct rho_bitmap *st_map;
    struct mdish_segment **st_opensegments; 
};

struct mdish_file {
    RHO_LIST_ENTRY(mdish_file) f_next_file;
    char        *f_name;
    uint64_t    f_lock_owner_id;
    int         f_refcnt;
};

RHO_LIST_HEAD(mdish_file_list, mdish_file);

struct mdish_fdtable {
    struct rho_bitmap *ft_map;
    struct mdish_file **ft_openfiles; /* array of pointers to open files */
};

struct mdish_client {
    RHO_LIST_ENTRY(mdish_client) cli_next_client;
    struct rpc_agent        *cli_agent;
    struct mdish_fdtable    *cli_fdtab;
    struct mdish_sdtable    *cli_sdtab;
    uint64_t                cli_id;
};

RHO_LIST_HEAD(mdish_client_list, mdish_client);

typedef void (*mdish_opcall)(struct mdish_client *client);

/**************************************
 * FORWARD DECLARATIONS
 **************************************/
/* segment funcs */
static struct mdish_segment * mdish_segment_find(const char *name);
static struct mdish_segment * mdish_segment_create(const char *name,
        size_t size);
static void mdish_segment_destroy(struct mdish_segment *seg);
static int mdish_segment_map(struct mdish_client *client, int fd, size_t size,
        int *sd);
static int mdish_segment_unmap(struct mdish_client *client, int sd);

/* sdtable (segment descriptor table) funcs  */
static struct mdish_sdtable * mdish_sdtable_create(void);
static struct mdish_sdtable * mdish_sdtable_copy(
        const struct mdish_sdtable *sdtab);
static void mdish_sdtable_destroy(struct mdish_client *client);
static void mdish_sdtable_expand(struct mdish_sdtable *sdtab);
static int mdish_sdtable_sdalloc(struct mdish_sdtable *sdtab);
static int mdish_sdtable_setopensegment(struct mdish_sdtable *sdtab,
        struct mdish_segment *seg);

/* file funcs */
static struct mdish_file * mdish_file_find(const char *name);
static struct mdish_file * mdish_file_create(const char *name);
static void mdish_file_destroy(struct mdish_file *fp);
static int mdish_file_open(struct mdish_client *client, const char *name,
        int *fd);
static int mdish_file_close(struct mdish_client *client, int fd);
static int mdish_file_lock(struct mdish_client *client, int fd);
static int mdish_file_unlock(struct mdish_client *client, int fd);

/* fdtable (file descriptor table) funcs */
static struct mdish_fdtable * mdish_fdtable_create(void);
static struct mdish_fdtable * mdish_fdtable_copy(
        const struct mdish_fdtable *fdtab);
static void mdish_fdtable_destroy(struct mdish_client *client);
static void mdish_fdtable_expand(struct mdish_fdtable *fdtab);
static int mdish_fdtable_fdalloc(struct mdish_fdtable *fdtab);
static int mdish_fdtable_setopenfile(struct mdish_fdtable *fdtab,
        struct mdish_file *fp);

/* RPC ops */
static void mdish_file_open_proxy(struct mdish_client *client);
static void mdish_file_close_proxy(struct mdish_client *client);
static void mdish_file_advlock_proxy(struct mdish_client *client);
static void mdish_file_advlock_lock_proxy_helper(
        struct mdish_client *client, int fd);
static void mdish_file_advlock_unlock_proxy_helper(
        struct mdish_client *client, int fd);
static void mdish_mmap_proxy(struct mdish_client *client);
static void mdish_munmap_proxy(struct mdish_client *client);

static void mdish_fork_proxy(struct mdish_client *client);
static void mdish_child_attach_proxy(struct mdish_client *client);
static void mdish_new_fdtable_proxy(struct mdish_client *client);

/* client funcs */
static void mdish_client_add(struct mdish_client *client);
static struct mdish_client * mdish_client_find(uint64_t id);

static struct mdish_client * mdish_client_alloc(void);
static struct mdish_client * mdish_client_create(struct rho_sock *sock);
static struct mdish_client * mdish_client_fork(struct mdish_client *parent);
static void mdish_client_splice(struct mdish_client *a,
        struct mdish_client *b);
static void mdish_client_destroy(struct mdish_client *client);

static void mdish_client_dispatch_call(struct mdish_client *client);
static void mdish_client_cb(struct rho_event *event, int what,
        struct rho_event_loop *loop);

/* server funcs */
static struct mdish_server * mdish_server_alloc(void);
static void mdish_server_destroy(struct mdish_server *server);
static void mdish_server_config_ssl(struct mdish_server *server,
        const char *cafile, const char *certfile, const char *keyfile);
static void mdish_server_socket_create(struct mdish_server *server,
        const char *udspath, bool anonymous);
static void mdish_server_cb(struct rho_event *event, int what,
        struct rho_event_loop *loop);

static void mdish_log_init(const char *logfile, bool verbose);

static void usage(int exitcode);

/**************************************
 * GLOBALS
 **************************************/

struct rho_log *mdish_log = NULL;

static struct mdish_client_list mdish_clients =
        RHO_LIST_HEAD_INITIALIZER(mdish_clients);

static struct mdish_segment_list mdish_segments =
        RHO_LIST_HEAD_INITIALIZER(mdish_segments);

static struct mdish_file_list mdish_files =
        RHO_LIST_HEAD_INITIALIZER(mdish_files);

static mdish_opcall mdish_opcalls[] = {
    [MDISH_OP_FILE_OPEN]    = mdish_file_open_proxy,
    [MDISH_OP_FILE_CLOSE]   = mdish_file_close_proxy,
    [MDISH_OP_FILE_ADVLOCK] = mdish_file_advlock_proxy,

    [MDISH_OP_MMAP]         = mdish_mmap_proxy,
    [MDISH_OP_MUNMAP]       = mdish_munmap_proxy,

    [MDISH_OP_FORK]         = mdish_fork_proxy,
    [MDISH_OP_CHILD_ATTACH] = mdish_child_attach_proxy,
    [MDISH_OP_NEW_FDTABLE]  = mdish_new_fdtable_proxy,
};

/**************************************
 * SEGMENT
 **************************************/
static struct mdish_segment *
mdish_segment_find(const char *name)
{
    struct mdish_segment *iter = NULL;

    RHO_TRACE_ENTER();

    RHO_LIST_FOREACH(iter, &mdish_segments, seg_next_segment) {
        if (rho_str_equal(iter->s_name, name))
            goto done;
    }
    rho_log_debug(mdish_log, "did not find segment \"%s\"\n", name);
    iter = NULL;

done:
    RHO_TRACE_EXIT();
    return (iter);
}

static struct mdish_segment *
mdish_segment_create(const char *name, size_t size)
{
    struct mdish_segment *seg = NULL;

    RHO_TRACE_ENTER();

    seg = rhoL_zalloc(sizeof(*seg));
    seg->s_name = rhoL_strdup(name);
    seg->s_addr = rhoL_zalloc(size);
    seg->s_size = size;
    seg->s_refcnt = 1;

    RHO_LIST_INSERT_HEAD(&mdish_segments, seg, seg_next_segment);

    RHO_TRACE_EXIT();
    return (seg);
}

static void
mdish_segment_destroy(struct mdish_segment *seg)
{
    seg->s_refcnt--;
    if (seg->s_refcnt > 0)
        goto done;

    RHO_LIST_REMOVE(seg, seg_next_segment);
    rhoL_free(seg->s_name);
    rhoL_free(seg->s_addr);
    rhoL_free(seg);

done:
    RHO_TRACE_EXIT();
    return;
}

static int
mdish_segment_map(struct mdish_client *client, int fd, size_t size, int *sd)
{
    int error = 0;
    struct mdish_fdtable *fdtab = client->cli_fdtab;
    struct mdish_file *fp = NULL;
    struct mdish_sdtable *sdtab = client->cli_sdtab;
    struct mdish_segment *seg = NULL;

    RHO_TRACE_ENTER();

    /* get the name associated with fd */
    if (!rho_bitmap_isset(fdtab->ft_map, fd)) {
        error = EBADF;
        goto done;
    }

    /* TODO: check if segment with this name already exists */

    fp = fdtab->ft_openfiles[fd];
    RHO_ASSERT(fp != NULL);

    seg = mdish_segment_create(fp->f_name, size);
    *sd = mdish_sdtable_setopensegment(sdtab, seg);

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
mdish_segment_unmap(struct mdish_client *client, int sd)
{
    int error = 0;
    struct mdish_sdtable *sdtab = client->cli_sdtab;
    struct mdish_segment *seg = NULL;

    RHO_TRACE_ENTER();
    
    if (!rho_bitmap_isset(sdtab->st_map, sd)) {
        error = EBADF;
        goto done;
    }

    seg = sdtab->st_opensegments[sd];
    RHO_ASSERT(seg != NULL);

    rho_bitmap_clear(sdtab->st_map, sd);
    mdish_segment_destroy(seg);

done:
    RHO_TRACE_EXIT();
    return (error);
}

/**************************************
 * SEGMENT TABLE
 **************************************/
static struct mdish_sdtable * 
mdish_sdtable_create(void)
{
    struct mdish_sdtable *sdtab = NULL;

    RHO_TRACE_ENTER();

    sdtab = rhoL_zalloc(sizeof(*sdtab));
    sdtab->st_map = rho_bitmap_create(true, 20);
    sdtab->st_opensegments = rhoL_mallocarray(20,
            sizeof(struct mdish_segment *), 0);

    RHO_TRACE_EXIT();
    return (sdtab);
}

static struct mdish_sdtable *
mdish_sdtable_copy(const struct mdish_sdtable *sdtab)
{
    struct mdish_sdtable *newp = NULL;
    struct mdish_segment *seg = NULL;
    size_t sd = 0;
    int bitval = 0;
    size_t n = 0;

    RHO_TRACE_ENTER();

    newp = rhoL_zalloc(sizeof(*newp));
    newp->st_map = rho_bitmap_copy(sdtab->st_map);

    n = rho_bitmap_size(sdtab->st_map);
    newp->st_opensegments = rhoL_mallocarray(
            n, sizeof(struct mdish_segment *), 0);
    
    RHO_BITMAP_FOREACH(sd, bitval, sdtab->st_map) {
        if (bitval == 0)
            continue;
        seg = sdtab->st_opensegments[sd];
        seg->s_refcnt++;
        newp->st_opensegments[sd] = seg;
    }

    RHO_TRACE_EXIT();
    return (newp);
}

static void
mdish_sdtable_destroy(struct mdish_client *client)
{
    struct mdish_sdtable *sdtab = client->cli_sdtab;
    size_t sd = 0;
    int bitval = 0;

    RHO_TRACE_ENTER();

    RHO_BITMAP_FOREACH(sd, bitval, sdtab->st_map) {
        if (bitval == 0)
            continue;
        /* TODO: what should we call here?
         * mdish_file_close(client, fd);
         */
    }

    rhoL_free(sdtab->st_opensegments);
    rho_bitmap_destroy(sdtab->st_map);
    rhoL_free(sdtab);

    RHO_TRACE_EXIT();
    return;
}

static void
mdish_sdtable_expand(struct mdish_sdtable *sdtab)
{
    size_t newmaxbits = 0;
    struct rho_bitmap *map = sdtab->st_map;

    RHO_TRACE_ENTER();
    
    /* TODO: check for overflow; also, check that this actually
     * expands, since the range of size_t is greater than int
     */
    newmaxbits = rho_bitmap_size(map) + 32;
    rho_bitmap_resize(map, newmaxbits);
    sdtab->st_opensegments = rhoL_reallocarray(sdtab->st_opensegments,
            newmaxbits, sizeof(struct mdish_segment *), 0);

    RHO_TRACE_EXIT();
}

static int
mdish_sdtable_sdalloc(struct mdish_sdtable *sdtab)
{
    int sd = 0;
    size_t oldmaxbits = 0;
    struct rho_bitmap *map = sdtab->st_map;

    RHO_TRACE_ENTER();

    /* TODO: you might want some upper limit on how many segments a client can
     * have open
     */
    sd = rho_bitmap_ffc(map);
    if (sd == -1) {
        oldmaxbits = rho_bitmap_size(map);
        mdish_sdtable_expand(sdtab);
        sd = oldmaxbits;
    }

    rho_bitmap_set(sdtab->st_map, sd);

    RHO_TRACE_EXIT("sd=%d", sd);
    return (sd);
}

static int
mdish_sdtable_setopensegment(struct mdish_sdtable *sdtab,
        struct mdish_segment *seg)
{
    int sd = 0;

    RHO_TRACE_ENTER();

    sd = mdish_sdtable_sdalloc(sdtab);
    sdtab->st_opensegments[sd] = seg;

    RHO_TRACE_EXIT("sd=%d", sd);
    return (sd);
}

/**************************************
 * FILE
 **************************************/

static struct mdish_file *
mdish_file_find(const char *name)
{
    struct mdish_file *iter = NULL;

    RHO_TRACE_ENTER();

    RHO_LIST_FOREACH(iter, &mdish_files, f_next_file) {
        if (rho_str_equal(name, iter->f_name))
            goto done;
    }
    iter = NULL;
    
done:
    RHO_TRACE_EXIT();
    return (iter);
}

static struct mdish_file *
mdish_file_create(const char *name)
{
    struct mdish_file *fp = NULL;

    RHO_TRACE_ENTER();
    
    fp = rhoL_zalloc(sizeof(*fp));
    fp->f_name = rhoL_strdup(name);
    fp->f_refcnt = 1;
    fp->f_lock_owner_id = MDISH_NO_OWNER;
    RHO_LIST_INSERT_HEAD(&mdish_files, fp, f_next_file);

    RHO_TRACE_EXIT();
    return (fp);
}

static void
mdish_file_destroy(struct mdish_file *fp)
{
    RHO_TRACE_ENTER();

    fp->f_refcnt--;
    if (fp->f_refcnt > 0)
        goto done;

    RHO_LIST_REMOVE(fp, f_next_file);
    rhoL_free(fp->f_name);
    rhoL_free(fp);

done:
    RHO_TRACE_EXIT();
    return;
}

static int
mdish_file_open(struct mdish_client *client, const char *name, int *fd)
{
    struct mdish_fdtable *fdtab = client->cli_fdtab;
    struct mdish_file *fp = NULL;

    RHO_TRACE_ENTER();

    fp = mdish_file_find(name);
    if (fp == NULL)
        fp = mdish_file_create(name);
    else
        fp->f_refcnt++;

    *fd = mdish_fdtable_setopenfile(fdtab, fp);

    RHO_TRACE_EXIT();
    return (0);
}

static int
mdish_file_close(struct mdish_client *client, int fd)
{
    int error = 0;
    struct mdish_fdtable *fdtab = client->cli_fdtab;
    struct mdish_file *fp = NULL;

    RHO_TRACE_ENTER();
    
    if (!rho_bitmap_isset(fdtab->ft_map, fd)) {
        error = EBADF;
        goto done;
    }

    fp = fdtab->ft_openfiles[fd];
    RHO_ASSERT(fp != NULL);
    if (fp->f_lock_owner_id == client->cli_id)
        fp->f_lock_owner_id = MDISH_NO_OWNER;

    rho_bitmap_clear(fdtab->ft_map, fd);
    mdish_file_destroy(fp);

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
mdish_file_lock(struct mdish_client *client, int fd)
{
    int error = 0;
    struct mdish_fdtable *fdtab = client->cli_fdtab;
    struct mdish_file *fp = NULL;

    RHO_TRACE_ENTER();

    if (!rho_bitmap_isset(fdtab->ft_map, fd)) {
        error = EBADF;
        goto done;
    }

    fp = fdtab->ft_openfiles[fd];
    RHO_ASSERT(fp != NULL);
    if (fp->f_lock_owner_id == MDISH_NO_OWNER) {
        fp->f_lock_owner_id = client->cli_id;
        goto done;
    }

    if (fp->f_lock_owner_id == client->cli_id)
        goto done;

    error = EAGAIN;

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
mdish_file_unlock(struct mdish_client *client, int fd)
{
    int error = 0;
    struct mdish_fdtable *fdtab = client->cli_fdtab;
    struct mdish_file *fp = NULL;

    RHO_TRACE_ENTER();

    if (!rho_bitmap_isset(fdtab->ft_map, fd)) {
        error = EBADF;
        goto done;
    }

    fp = fdtab->ft_openfiles[fd];
    RHO_ASSERT(fp != NULL);
    if (fp->f_lock_owner_id == client->cli_id)
        fp->f_lock_owner_id = MDISH_NO_OWNER;

    /*
     * XXX:
     * flock(2) semenatics are to return success (e.g., 0) when trying
     * to lock a nonexistant lock or a lock held by someone else.  fcntl(2)
     * might be different.   For now, just follow flock(2).
     *
     * Note that if we follow flock(2)'s return value behavior, then
     * we're allowing client to upload it's memview simply by calling
     * unlock, regardless of whether the client has the lock.
     *
     * We can probably keep flock sementics but avoid such un-authorized
     * uploads of the memview with a little extra code.
     */

done:
    RHO_TRACE_EXIT();
    return (error);
}

/**************************************
 * FDTABLE
 **************************************/

static struct mdish_fdtable *
mdish_fdtable_create(void)
{
    struct mdish_fdtable *fdtab = NULL;

    RHO_TRACE_ENTER();

    fdtab = rhoL_zalloc(sizeof(*fdtab));
    fdtab->ft_map = rho_bitmap_create(true, 20);
    fdtab->ft_openfiles = rhoL_mallocarray(20, sizeof(struct mdish_file *), 0);

    RHO_TRACE_EXIT();
    return (fdtab);
}

static struct mdish_fdtable *
mdish_fdtable_copy(const struct mdish_fdtable *fdtab)
{
    struct mdish_fdtable *newp = NULL;
    struct mdish_file *fp = NULL;
    size_t fd = 0;
    int bitval = 0;
    size_t n = 0;

    RHO_TRACE_ENTER();

    newp = rhoL_zalloc(sizeof(*newp));
    newp->ft_map = rho_bitmap_copy(fdtab->ft_map);

    n = rho_bitmap_size(fdtab->ft_map);
    newp->ft_openfiles = rhoL_mallocarray(n, sizeof(struct mdish_file *), 0);
    
    RHO_BITMAP_FOREACH(fd, bitval, fdtab->ft_map) {
        if (bitval == 0)
            continue;
        fp = fdtab->ft_openfiles[fd];
        fp->f_refcnt++;
        newp->ft_openfiles[fd] = fp;
    }

    RHO_TRACE_EXIT();
    return (newp);
}

static void
mdish_fdtable_destroy(struct mdish_client *client)
{
    struct mdish_fdtable *fdtab = client->cli_fdtab;
    size_t fd = 0;
    int bitval = 0;

    RHO_TRACE_ENTER();

    RHO_BITMAP_FOREACH(fd, bitval, fdtab->ft_map) {
        if (bitval == 0)
            continue;
        mdish_file_close(client, fd);
    }

    rhoL_free(fdtab->ft_openfiles);
    rho_bitmap_destroy(fdtab->ft_map);
    rhoL_free(fdtab);

    RHO_TRACE_EXIT();
    return;
}

static void
mdish_fdtable_expand(struct mdish_fdtable *fdtab)
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
            newmaxbits, sizeof(struct mdish_file *), 0);

    RHO_TRACE_EXIT();
}

/*
 * Allocate a file descriptor for the client.
 */
static int
mdish_fdtable_fdalloc(struct mdish_fdtable *fdtab)
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
        mdish_fdtable_expand(fdtab);
        fd = oldmaxbits;
    }

    rho_bitmap_set(fdtab->ft_map, fd);

    RHO_TRACE_EXIT("fd=%d", fd);
    return (fd);
}

/*
 * Allocate and bind a client's file (segment) descriptor
 */
static int
mdish_fdtable_setopenfile(struct mdish_fdtable *fdtab, struct mdish_file *fp)
{
    int fd = 0;

    RHO_TRACE_ENTER();

    fd = mdish_fdtable_fdalloc(fdtab);
    fdtab->ft_openfiles[fd] = fp;

    RHO_TRACE_EXIT("fd=%d", fd);
    return (fd);
}

/**************************************
 * FILE RPC OPERATIONS
 **************************************/

/*
 * open(const char *name) -> fd {uint32_t}
 */
static void
mdish_file_open_proxy(struct mdish_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    char name[MDISH_MAX_NAME_LENGTH + 1] = { 0 };
    int fd = -1;

    RHO_TRACE_ENTER();

    error = rho_buf_read_u32size_str(buf, name, sizeof(name));
    if (error != 0) {
        error = EPROTO;
        goto done;
    }

    error = mdish_file_open(client, name, &fd);

done:
    rpc_agent_new_msg(agent, error);
    if (error) {
        rho_log_errno_debug(mdish_log, error, "id=0x%"PRIx64" open(\"%s\")",
            client->cli_id, name);
    } else {
        rpc_agent_set_bodylen(agent, 4);
        rho_buf_writeu32be(buf, fd);
        rho_log_errno_debug(mdish_log, error, "id=0x%"PRIx64" open(\"%s\") -> %d",
            client->cli_id, name, fd);
    }
    RHO_TRACE_EXIT();
    return;
}

/*
 * close(int fd)
 */
static void
mdish_file_close_proxy(struct mdish_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint32_t fd = -1;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, &fd);        
    if (error == -1) {
        error = MDISH_ERPC;
        goto done;
    }

    error = mdish_file_close(client, fd);

done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(mdish_log, error, "id=0x%"PRIx64" close(\"%d\")",
        client->cli_id, fd);

    RHO_TRACE_EXIT();
    return;
}

/*
 * lock(int fd, int op)
 *
 * MDISH_LOCKOP_LOCK:
 *  req:   op    | bodylen |  fd
 *  resp:  error | bodylen | membuf
 *
 * MDISH_LOCKOP_UNLOCK:
 *  req:   op    | bodylen |  fd | membuf
 *  resp:  error | bodylen 
 */
static void
mdish_file_advlock_proxy(struct mdish_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint32_t fd = 0;
    uint32_t lockop = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, &fd);
    if (error == -1) {
        error = MDISH_ERPC;
        goto fail;
    }

    error = rho_buf_readu32be(buf, &lockop);
    if (error == -1) {
        error = MDISH_ERPC;
        goto fail;
    }

    rho_log_debug(mdish_log, "id=0x%"PRIx64" lock(fd=%"PRIu32", op=%"PRIu32")\n",
            client->cli_id, fd, lockop);

    if (lockop == MDISH_LOCKOP_LOCK)
        mdish_file_advlock_lock_proxy_helper(client, fd);
    else if (lockop == MDISH_LOCKOP_UNLOCK)
        mdish_file_advlock_unlock_proxy_helper(client, fd);
    else
        rpc_agent_new_msg(agent, EINVAL);

fail:
    RHO_TRACE_EXIT();
    return;
}

static void
mdish_file_advlock_lock_proxy_helper(struct mdish_client *client, int fd)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct mdish_fdtable *fdtab = client->cli_fdtab;
    struct mdish_file *fp = NULL;
    struct mdish_segment *seg = NULL;

    RHO_TRACE_ENTER();

    error = mdish_file_lock(client, fd);
    if (error != 0) {
        goto done;
    }

    fp = fdtab->ft_openfiles[fd];
    RHO_ASSERT(fp != NULL);

    /* 
     * FIXME: this assumes that if the segment exists, *this* client
     * has it mapped.
     */
#if 0
    seg = mdish_segment_find(fp->f_name); 
     if (seg == NULL || !seg->s_modified) {
        error = ENOENT;
        goto done;
    }
#endif
     if (seg == NULL) {
         rho_debug("fd is a pure lock");
     }

done:
    rpc_agent_new_msg(agent, error);
    if (!error) {

        if (seg != NULL) {
            rpc_agent_set_bodylen(agent, seg->s_size);
            rho_buf_write(buf, seg->s_addr, seg->s_size);   /* body */
            rho_log_errno_debug(mdish_log, error, "id=0x%"PRIx64" lock_lock(fd=%"PRIu32") -> {%p, %u}",
                    client->cli_id, fd, seg->s_addr, seg->s_size);
        } else {
            rho_log_errno_debug(mdish_log, error, "id=0x%"PRIx64" lock_lock(fd=%"PRIu32") -> {%p, %u}",
                    client->cli_id, fd);
        }
    } else {
        rho_log_errno_debug(mdish_log, error, "id=0x%"PRIx64" lock_lock(fd=%"PRIu32")",
                client->cli_id, fd);
    }

    RHO_TRACE_EXIT();
    return;
}

static void
mdish_file_advlock_unlock_proxy_helper(struct mdish_client *client, int fd)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct mdish_fdtable *fdtab = client->cli_fdtab;
    struct mdish_file *fp = NULL;
    struct mdish_segment *seg = NULL;
    size_t memsize = 0;
    void *mem = NULL; 

    RHO_TRACE_ENTER();

    error = mdish_file_unlock(client, fd);
    if (error != 0)
        goto done;

    fp = fdtab->ft_openfiles[fd];
    RHO_ASSERT(fp != NULL);

    /* 
     * FIXME: this again assumes that if the segment exists, then
     * *this* client has the segment mapped
     */
    seg = mdish_segment_find(fp->f_name); 
    if (seg == NULL) {
        /* TODO: make sure there is no data in the buffer */
        goto done;
    }

    memsize = rho_buf_length(buf) - rho_buf_tell(buf);
    fprintf(stderr, "************ unlocking (memize: %zu)\n", memsize);
    if (memsize != seg->s_size) {
        fprintf(stderr, "memsize=%zu, and seg->size=%zu\n", memsize, seg->s_size);
        /* TODO: probably choose different errno */ 
        error = ENOSPC;
        goto done;
    }

    mem = rho_buf_raw(buf, 0, SEEK_CUR);
    memcpy(seg->s_addr, mem, seg->s_size);
    seg->s_modified = true;
    //rho_hexdump(seg->addr, seg->size, "shared memory after unlock:\n");

done:
    rpc_agent_new_msg(agent, error);
    rho_log_errno_debug(mdish_log, error, "id=0x%"PRIx64" lock_unlock(fd=%"PRIu32")",
        client->cli_id, fd);
    RHO_TRACE_EXIT();
    return;
}

/*
 * mmap(int fd, size_t size)
 */
static void
mdish_mmap_proxy(struct mdish_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint32_t fd = 0;
    uint32_t sd = 0;
    uint32_t size = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, &fd);
    if (error == -1) {
        error = MDISH_ERPC;
        goto done;
    }

    error = rho_buf_readu32be(buf, &size);        
    if (error == -1) {
        error = MDISH_ERPC;
        goto done;
    }

    error = mdish_segment_map(client, (int)fd, size, (int *)&sd);

done:
    rpc_agent_new_msg(agent, error);
    if (error) {
        rho_log_errno_debug(mdish_log, error, "id=-x%"PRIx64" mmap(%d, %"PRIu32")",
            client->cli_id, fd, size);
    } else {
        rpc_agent_set_bodylen(agent, 4);
        rho_buf_writeu32be(buf, sd);
        rho_log_errno_debug(mdish_log, error, "id=0x%"PRIx64" mmap(%d, %"PRIu32") -> %d",
            client->cli_id, fd, size, sd);
    }
    RHO_TRACE_EXIT();
    return;
}

/*
 * TODO: POSTPONE
 */
static void
mdish_munmap_proxy(struct mdish_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint32_t sd = 0;

    RHO_TRACE_ENTER();

    error = rho_buf_readu32be(buf, &sd);
    if (error == -1) {
        error = MDISH_ERPC;
        goto done;
    }

    fprintf(stderr, "**** [client=%"PRIx64"] munmap(sd=%"PRIu32"\n",
            client->cli_id, sd);

    error = mdish_segment_unmap(client, sd);

done:
    rpc_agent_new_msg(agent, error);
    RHO_TRACE_EXIT();
    return;
}

/**************************************
 * FORK/EXEC RPC OPERATIONS
 **************************************/

static void
mdish_fork_proxy(struct mdish_client *client)
{
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    struct mdish_client *child = NULL;
    uint64_t id = 0;

    RHO_TRACE_ENTER();

    child = mdish_client_fork(client);
    mdish_client_add(child);
    id = child->cli_id;

    rpc_agent_new_msg(agent, 0);
    rpc_agent_set_bodylen(agent, 8);
    rho_buf_writeu64be(buf, id);

    rho_log_errno_debug(mdish_log, 0, "id=0x%"PRIx64" fork() -> 0x%"PRIx64,
        client->cli_id, id);

    RHO_TRACE_EXIT();
    return;
}

static void
mdish_child_attach_proxy(struct mdish_client *client)
{
    int error = 0;
    struct rpc_agent *agent = client->cli_agent;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint64_t id;
    struct mdish_client *attachee = NULL;;

    RHO_TRACE_ENTER();

    error = rho_buf_readu64be(buf, &id);
    if (error == -1) {
        /* 
         * TODO: we might want to replace MDISH_ERPC with EREMOTEIO,
         * which, I think, is a non-POSIX errno value that Linux uses
         */
        error = MDISH_ERPC;
        goto done;
    }

    attachee = mdish_client_find(id);
    if (attachee == NULL) {
        /* XXX: there might be a more specific errno value for this scenario */
        error = EINVAL;
        goto done;
    }

    mdish_client_splice(client, attachee);
    
done:
    rpc_agent_new_msg(agent, error);

    rho_log_errno_debug(mdish_log, error, "id=0x%"PRIx64" child_attach()",
        client->cli_id);

    RHO_TRACE_EXIT();
    return;
}

static void
mdish_new_fdtable_proxy(struct mdish_client *client)
{
    struct rpc_agent *agent = client->cli_agent;

    RHO_TRACE_ENTER();

    if (client->cli_fdtab != NULL)
        mdish_fdtable_destroy(client);

    client->cli_fdtab = mdish_fdtable_create();
    client->cli_sdtab = mdish_sdtable_create();

    rpc_agent_new_msg(agent, 0);

    rho_log_errno_debug(mdish_log, 0, "id=0x%"PRIx64" new_fdtable()",
        client->cli_id);

    RHO_TRACE_EXIT();
    return;
}

/**************************************
 * CLIENT
 **************************************/

static struct mdish_client *
mdish_client_find(uint64_t id)
{
    struct mdish_client *iter = NULL;

    RHO_TRACE_ENTER();

    RHO_LIST_FOREACH(iter, &mdish_clients, cli_next_client) {
        if (iter->cli_id == id)
            goto done;
    }
    iter = NULL;

done:
    RHO_TRACE_EXIT();
    return (iter);
}

static void
mdish_client_add(struct mdish_client *client)
{
    uint64_t id = 0;
    struct mdish_client *iter = NULL;

    RHO_TRACE_ENTER();

    /* find a unique client id */
    do {
again:
        id = rho_rand_u64();
        RHO_LIST_FOREACH(iter, &mdish_clients, cli_next_client) {
            if (iter->cli_id == id)
                goto again;
        }
        break;
    } while (1);

    client->cli_id = id;
    RHO_LIST_INSERT_HEAD(&mdish_clients, client, cli_next_client);

    RHO_TRACE_EXIT("");
    return;
}

static struct mdish_client *
mdish_client_alloc(void)
{
    struct mdish_client *client = NULL;

    RHO_TRACE_ENTER();

    client = rhoL_zalloc(sizeof(*client));
    client->cli_agent = rpc_agent_create(NULL, NULL);

    RHO_TRACE_EXIT();
    return (client);
}

static struct mdish_client *
mdish_client_create(struct rho_sock *sock)
{
    struct mdish_client *client = NULL;
    struct rpc_agent *agent = NULL;

    RHO_TRACE_ENTER();

    client = mdish_client_alloc();
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

static struct mdish_client *
mdish_client_fork(struct mdish_client *parent)
{
    struct mdish_client *client = NULL;

    RHO_TRACE_ENTER();

    client = mdish_client_alloc();
    client->cli_fdtab = mdish_fdtable_copy(parent->cli_fdtab);
    client->cli_sdtab = mdish_sdtable_copy(parent->cli_sdtab);

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
mdish_client_splice(struct mdish_client *a, struct mdish_client *b)
{
    RHO_TRACE_ENTER();

    a->cli_fdtab = b->cli_fdtab;
    b->cli_fdtab = NULL;

    a->cli_sdtab = b->cli_sdtab;
    b->cli_sdtab = NULL;

    RHO_LIST_REMOVE(b, cli_next_client);
    mdish_client_destroy(b);

    RHO_TRACE_EXIT();
    return;
};

static void
mdish_client_destroy(struct mdish_client *client)
{
    RHO_ASSERT(client != NULL);

    RHO_TRACE_ENTER("id=0x%"PRIx64, client->cli_id);
    
    rpc_agent_destroy(client->cli_agent);

    if (client->cli_fdtab != NULL)
        mdish_fdtable_destroy(client);
    if (client->cli_sdtab != NULL)
        mdish_sdtable_destroy(client);

    rhoL_free(client);

    RHO_TRACE_EXIT("");
}

static void
mdish_client_dispatch_call(struct mdish_client *client)
{
    struct rpc_agent *agent = client->cli_agent;
    uint32_t opcode = agent->ra_hdr.rh_code;
    mdish_opcall opcall = NULL;

    RHO_ASSERT(agent->ra_state == RPC_STATE_DISPATCHABLE);
    RHO_ASSERT(rho_buf_tell(agent->ra_bodybuf) == 0);

    RHO_TRACE_ENTER("fd=%d, opcode=%d", agent->ra_sock->fd, opcode);

    if (opcode >= RHO_C_ARRAY_SIZE(mdish_opcalls)) {
        rho_log_warn(mdish_log, "bad opcode (%"PRIu32")", opcode);
        rpc_agent_new_msg(agent, ENOSYS);
        goto done;
    } 

    if ((client->cli_fdtab == NULL) && 
        ((opcode != MDISH_OP_NEW_FDTABLE) && (opcode != MDISH_OP_CHILD_ATTACH))) {
        rho_log_warn(mdish_log,
                "client attempting file operations without an fdtable");
        rpc_agent_new_msg(agent, EPERM);
        goto done;
    }

    opcall = mdish_opcalls[opcode];
    opcall(client);

done:
    rpc_agent_ready_send(agent);
    RHO_TRACE_EXIT();
    return;
}

static void
mdish_client_cb(struct rho_event *event, int what, struct rho_event_loop *loop)
{
    int ret = 0;
    struct mdish_client *client = NULL;
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
        mdish_client_dispatch_call(client);

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
    rho_log_info(mdish_log, "id=0x%"PRIx64" disconnected", client->cli_id);
    mdish_client_destroy(client);
    RHO_TRACE_EXIT("client done");
    return;
}

/**************************************
 * SERVER
 **************************************/

static struct mdish_server *
mdish_server_alloc(void)
{
    struct mdish_server *server = NULL;
    server = rhoL_zalloc(sizeof(*server));
    return (server);
}

static void
mdish_server_destroy(struct mdish_server *server)
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
mdish_server_config_ssl(struct mdish_server *server,
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
mdish_server_socket_create(struct mdish_server *server, const char *udspath,
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
mdish_server_cb(struct rho_event *event, int what, struct rho_event_loop *loop)
{
    int cfd = 0;
    struct sockaddr_un addr;
    socklen_t addrlen = sizeof(addr);
    struct rho_event *cevent = NULL;
    struct mdish_client *client = NULL;
    struct mdish_server *server = NULL;
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
    client = mdish_client_create(csock);
    mdish_client_add(client);
    rho_log_info(mdish_log, "new connection: id=0x%"PRIx64, client->cli_id);
    /* XXX: memory leak? -- where do we destroy the event? */
    cevent = rho_event_create(cfd, RHO_EVENT_READ, mdish_client_cb, client);
    client->cli_agent->ra_event = cevent;
    rho_event_loop_add(loop, cevent, NULL); 
}

/**************************************
 * LOG
 **************************************/

static void
mdish_log_init(const char *logfile, bool verbose)
{
    int fd = STDERR_FILENO;

    if (logfile != NULL) {
        fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT,
                S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH,S_IWOTH);
        if (fd == -1)
            rho_errno_die(errno, "can't open or creat logfile \"%s\"", logfile);
    }

    mdish_log = rho_log_create(fd, RHO_LOG_INFO, rho_log_default_writer, NULL);

    if (verbose) 
        rho_log_set_level(mdish_log, RHO_LOG_DEBUG);

    if (logfile != NULL) {
        rho_log_redirect_stderr(mdish_log);
        (void)close(fd);
    }
}

#define MDISHSERVER_USAGE \
    "usage: mdish [options] UDSPATH\n" \
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
    fprintf(stderr, "%s\n", MDISHSERVER_USAGE);
    exit(exitcode);
}

int
main(int argc, char *argv[])
{
    int c = 0;
    struct mdish_server *server = NULL;
    struct rho_event *event = NULL;
    struct rho_event_loop *loop = NULL;
    /* options */
    bool anonymous = false;
    bool daemonize  = false;
    const char *logfile = NULL;
    bool verbose = false;

    rho_ssl_init();

    server  = mdish_server_alloc();
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
            mdish_server_config_ssl(server, optarg, argv[optind], argv[optind + 1]);
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

    mdish_log_init(logfile, verbose);

    mdish_server_socket_create(server, argv[0], anonymous);

    event = rho_event_create(server->srv_sock->fd, RHO_EVENT_READ | RHO_EVENT_PERSIST, 
            mdish_server_cb, server); 

    loop = rho_event_loop_create();
    rho_event_loop_add(loop, event, NULL); 
    rho_event_loop_dispatch(loop);

    /* TODO: destroy event and event_loop */

    mdish_server_destroy(server);
    rho_ssl_fini();

    return (0);
}
