#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include <rho/rho.h>

/*
 * 0            1       2        3       4
 * ./mdishbench MEMPATH LOCKPATH MEMSIZE ITERATIONS
 *
 * The program calculates how long (wall clock time) it takes to make
 * ITERATIONS number of locks/unlocks (that is, evaluate n critical sections).
 *
 * MEMSIZE is in bytes.
 *
 *
 * To test on normal Linux, use:
 *
 *  # 1k   (really mmaps a 4k)
 *  ./mdishbench /dev/zero mylock 1024 10000
 *
 *  # 10K   (really maps 3*1024 = 12288 bytes)
 *  ./mdishbench /dev/zero mylock 10240 10000
 *
 *  # 100K
 *  ./mdishbench /dev/zero mylock 102400 10000
 *
 *  # 1M
 *  ./mdishbench /dev/zero mylock 1048576 10000
 *
 * To test on graphene, use:
 *
 *  # 1k   (really mmaps a 4k)
 *  ./mdishbench /memserver/test /memserver/test 1024 10000
 *
 *  # 10K   (really maps 3*1024 = 12288 bytes)
 *  ./mdishbench /memserver/test /memserver/test 10240 10000
 *
 *  # 100K
 *  ./mdishbench /memserver/test /memserver/test 102400 10000
 *
 *  # 1M
 *  ./mdishbench /memserver/test /memserver/test 1048576 10000
 */

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
    int i = 0;
    int n = 0;
    unsigned int memsize = 0;
    int fd = 0;
    char *data = NULL;
    struct timeval start;
    struct timeval tmp;
    struct timeval end;
    struct timeval elapsed;
    double secs;

    if (argc != 5) {
        fprintf(stderr, "usage: %s MEMPATH LOCKPATH MEMSIZE ITERATIONS\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    memsize = rho_str_touint(argv[3], 10);
    n = rho_str_toint(argv[4], 10);

    /* map memory */
    fd = open(argv[1], O_RDWR);
    if (fd == -1)
        rho_errno_die(errno, "open(\"%s\", O_RDWR) failed", argv[1]);

    data = mmap(NULL, memsize, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (data == NULL)
        rho_errno_die(errno, "mmap(path=\"%s\", size=%u", argv[1], memsize);

    close(fd);

    /* create lock file */
    fd = open(argv[2], O_RDWR|O_CREAT, 0644);
    if (fd == -1)
        rho_errno_die(errno, "can't create lockfile: open(\"%s\", O_RDWR failed)",
                argv[2]);


    /* do benchmark */
    (void)gettimeofday(&start, NULL);
    for (i = 0; i < n; i++) {
        lockfd(fd);
        data[0] = 'A';
        unlockfd(fd);
        if (((i+1) % 100000) == 0)
            printf("completed %d\n", i+1);
    }
    (void)gettimeofday(&end, NULL);

    /* report times */
    rho_timeval_subtract(&end, &start, &elapsed);
    secs = rho_timeval_to_sec_double(&elapsed);

    printf("critical sections: %d, elapsed: secs:%ld, usec:%ld\n",
            n, (long)elapsed.tv_sec, (long)elapsed.tv_usec);
    printf("(%.9f seconds per critical section)\n", secs / n);

    /* cleanup */
    close(fd);
    // TODO: munmap

    return (0);
}
