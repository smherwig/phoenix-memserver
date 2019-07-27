Overview
========


Use Cases
=========
The shared memory implementation need ot handle four-uses:

*Pure lock*
```
open    (for lock)

lock
unlock
...
lock
unlock

close
```

*mmap, then lock*
```
open    (for mmap)
mmap
close

open    (for lock)
lock
unlock
...
lock
unlock
close       # close and munmap can be flipped
munmap
```

*lock, then map*
```
open    (for lock)

open    (for mmap)
mmap
close

lock
unlock
...
lock
unlock

close       # close and munmap can be flipped
munmap

*lock and mmpa together*
```
open (for lock and mmap)
mmap

lock
unlock
...
lock
unlock

close       # close and munma can be swiched.
munmap


Properties
==========
We call the abstraction of a file representing a lock and (optionally) a share
dmemory segment a _memfile_.  memfiles are non-persisstent.  They are created
on the first open; they are destoryed when no process holds an fd to the file
or has the segment mapped.

We assume that `mmap` and the `open` for the lock occur in the parent, so that
child processes inherit the memory segment and the lock file fd over fork.  A
(rare?) case that we should suppos is wher ethe parrent `mmap`s the file and
the closes the fd before forking, and the child reopens the file.  Here, the
parent either never actually reads or writes to the semgnet, or the parent
reopens the file after the fork.

A proces can have many fds for the same memffile.  If any one fo the fds is
`mmap`'d, all fds act as pointing to a memfile with associated memory, rather
thanjust a pure lock file.

From the perspective of the libOS, memfiles only support `open`, `close`,
`mmap`, `lock`, and `unlock` (the latter two via `fcntl`).  (memfiles would
also support `munmap` if the libOs has a unified vma and filesystem design).
Any flags to open are ignore.d  `mmap` always acts as `MAP_SHARED` and
`PROT_READ|PROT_WRITE`.

The shared memory filesytem is flat; there are no directories.


SMDISH Protocol
===============

`new_fdtable`
-------------

### Request

```
Header:
    u32         op_code     0
    u32         body_size   0
```

### Response

The response is always success:

```
Header:
    u32         status      0
    u32         body_size   0
```



`fork`
------

### Request

```
Header:
    u32         op_code     1
    u32         body_size   0
```

### Response


On success, the response includes a bearer token, `child_ident`, for
the child.  The child process should present `child_ident`  to the server
in a `child_attach` RPC in order to attach to the cloned file descriptor table.

```
Header:
    u32         status      0
    u32         body_size   8
Body:
    u64         child_ident
```

On failure, the response is

```
Header:
    u32         status      
    u32         body_size   0
```

Where status is:

- `EPERM`
    The client does not have an fdtable.



`child_attach`
--------------

### Request

```
Header:
    u32         op_code     2
    u32         body_size   8
Body:
    u64         child_ident
```

### Response

```
Header:
    u32         status      
    u32         body_size   0
```

On success, `status` is `0`.  On failure, `status` is one of the following:

- `EPROTO`
    The RPC request was malformed.
- `EINVAL`
    `child_ident` is not a valid token.


`open`
------

### Request

```
Header:
    u32         op_code     3
    u32         body_size
Body:
    u32         name_len
    bytearray   name
```

### Response

On success:

```
Header:
    u32         status      0
    u32         body_size   4
Body:
    u32         fd
```

On failure:

```
Header:
    u32         status      
    u32         body_size   0
```

Where status is one of the following errno values

- `EPERM`
    The client does not have an fdtable.
- `EPROTO`
    The RPC request was malformed.
- `ENAMETOOLONG`
    `name` is too long.  The longest name currently allowed is 255 characters
    (no nuls).


`close`
-------

### Request

```
Header:
    u32         op_code     4
    u32         body_size   4
Body:
    u32         fd
```

The response is

```
Header:
    u32         status      
    u32         body_size   0
```

Where status is `0` on success, and one of the following errno values
on failure:

- `EPERM`
    The client does not have an fdtable.
- `EPROTO`
    The RPC request was malformed.
- `EBADF`
    `fd` isn't a valid open file descriptor.


### Response


`lock`
------

### Request

```
Header:
    u32         op_code     5
    u32         body_size   4
Body:
    u32         fd
```

### Response

If fd is a pure lock (that is, does not have a memory mapping), then the
response is:

```
Header:
    u32         status  
    u32         body_size   0
```

On success (that is, if the client acquires the lock), `status` is `0`.
Otherwise, `status` is one of the following errno values:

- `EPERM`
    The client does not have an fdtable.
- `EPROTO`
    The RPC request was malformed.
- `EBADF`
    `fd` isn't a valid open file descriptor.
- `EAGAIN`
    The lock is currently held by another client.

If the fd represented a lock with associated memory, the on success (that is,
if the client aquires the lock, the response is:

```
Header:
    u32         status      0
    u32         body_size   
Body:
    u32         data_size
    bytearray   data
```

On failure, the response is

```
Header:
    u32         status      
    u32         body_size   0
```

where `status` is one of the following values:

- `EPERM`
    The client does not have an fdtable.
- `EPROTO`
    The RPC request was malformed.
- `EBADF`
    `fd` isn't a valid open file descriptor.


`unlock`
--------

### Request

If the file is a pure lock (that is, the file is not associated with an)
shared memory, the request is:

```
Header:
    u32         op_code     6
    u32         body_size   
Body:
    u32         fd
```

If the file is associated with shared memory, the request is:

```
Header:
    u32         op_code     6
    u32         body_size   
Body:
    u32         fd
    u32         data_size
    u32         data
```

### Response

The response is:

```
Header:
    u32         status      
    u32         body_size   0
```

On success, `status` is `0`.  On failure, `status` is one of the following:

- `EPERM`
    The client does not have an fdtable.
- `EPROTO`
    The RPC request was malformed.
- `EBADF`
    `fd` isn't a valid open file descriptor.
- `EINVAL`
    The client is trying to unlock a file for which it does not possess the
    lock.  Or, the client's segment replica is not the same size as the
    server's replica.
- 


`mmap`
------

### Request

```
Header:
    u32         op_code     7
    u32         body_size   8
Body:
    u32         fd
    u32         size
```

### Response

On success, the response is

```
Header:
    u32         status      0
    u32         body_size   4
Body:
    u32         mapfd
```

On failure, the reponse is

```
Header:
    u32         status      0
    u32         body_size   4
```

and `status` is one of the following errno values:

- `EPERM`
    The client does not have an fdtable.
- `EPROTO`
    The RPC request was malformed.
- `EBADF`
    `fd` isn't a valid open file descriptor.


Deploying
=========




Benchmarking
============
```
    ./make_sgx.py -g ~/ws/phoenix -k private.pem -p \
        ~/phoenix/memserver/bench/smbench.conf  -t $PWD -v -o smbench

# outside of sgx
    ./smufserver -Z root.crt proc.crt proc.key -r
        /home/smherwig/phoenix/memfiles -a /graphene/123456/77ea98e9

# inside of sgx
    ./smufserver.manifest.sgx -Z /srv/root.crt /srv/proc.crt /srv/proc.key
        -r /memfiles /etc/ramones

```
