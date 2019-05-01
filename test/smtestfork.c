#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include <rho/rho.h>

#define MEMSIZE 4096

static void
lockfd(int fd)
{
    struct flock  fl;

    rho_memzero(&fl, sizeof(struct flock));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;

    if (fcntl(fd, F_SETLKW, &fl) == -1)
        rho_die("lockfd failed");
}

static void
unlockfd(int fd)
{
    struct flock  fl;

    rho_memzero(&fl, sizeof(struct flock));
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;

    if (fcntl(fd, F_SETLK, &fl) == -1)
        rho_die("unlockfd failed");
}

int
main(int argc, char *argv[])
{
    int error = 0;
    int i = 0;
    int n = 0;
    int fd = 0;
    char *data = NULL;
    pid_t pid = 0;
    const char *mem_path = NULL;
    const char *lock_path = NULL;

    if (argc != 4) {
        fprintf(stderr, "usage: %s MEMPATH LOCKPATH ITERATIONS\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    mem_path = argv[1];
    lock_path = argv[2];
    n = rho_str_toint(argv[3], 10);

    /* map memory */
    fd = open(mem_path, O_RDWR);
    if (fd == -1)
        rho_errno_die(errno, "open(\"%s\", O_RDWR) failed", mem_path);

    data = mmap(NULL, MEMSIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (data == NULL)
        rho_errno_die(errno, "mmap(path=\"%s\", size=%u", mem_path, MEMSIZE);

    close(fd);

    /* create lock file */
    fd = open(lock_path, O_RDWR|O_CREAT, 0644);
    if (fd == -1)
        rho_errno_die(errno, "can't create lockfile: open(\"%s\", O_RDWR failed)",
                lock_path);

    pid = fork();
    if (pid == -1) {
        rho_errno_die(errno, "fork");
    } else if (pid == 0) {
        /* child */
        for (i = 0; i < n; i++) {
            lockfd(fd);
            data[16 + i] = 'C';
            unlockfd(fd);
        }
        error = close(fd);
        if (error != 0)
            rho_errno_warn(errno, "close");
    } else {
        /* parent */
        for (i = 0; i < n; i++) {
            lockfd(fd);
            data[0 + i] = 'P';
            unlockfd(fd);
        }
        error = close(fd);
        if (error != 0)
            rho_errno_warn(errno, "close");

        if (waitpid(pid, &error, 0) == -1) {
            rho_errno_warn(errno, "waitpid");
        } else {
            printf("child returns %d\n", error);
            rho_hexdump(data, 100, "shared memory");
        }
    }

    return (0);
}
