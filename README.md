Overview
========


Protocol
========


`open`
------

### Request

```
Header:
    u32         op_code     0
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
    u32         op_code     1
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
    u32         op_code     2
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

- `EPROTO`
    The RPC request was malformed.
- `EBADF`
    `fd` isn't a valid open file descriptor.


`unlock`
--------

### Request

```
Header:
    u32         op_code     3
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

- `EPROTO`
    The RPC request was malformed.
- `EBADF`
    `fd` isn't a valid open file descriptor.
- `EINVAL`
    The client is trying to unlock a file for which it does not possess the
    lock.

`mmap`
------

### Request

```
Header:
    u32         op_code     4
    u32         body_size   8
Body:
    u32         fd
    u32         size
```

### Response

The response is

```
Header:
    u32         status     
    u32         body_size   0 
```

On success, `status` is `0`; on error, `status` is one of the following
errno values:

- `EPROTO`
    The RPC request was malformed.
- `EBADF`
    `fd` isn't a valid open file descriptor.


`munmap`
--------

### Request

```
Header:
    u32         op_code     5
    u32         body_size   4
Body:
    u32         fd
```

### Response

The response is

```
Header:
    u32         status     
    u32         body_size   0 
```

On success, `status` is `0`; on error, `status` is one of the following
errno values:

- `EPROTO`
    The RPC request was malformed.
- `EBADF`
    `fd` isn't a valid open file descriptor.
- `EINVAL`
    The file does not have any memory mapped (the file is a pure lock file).


`new_fdtable`
-------------

### Request

```
Header:
    u32         op_code     6
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
    u32         op_code     7
    u32         body_size   0
```

### Response

The response is always success, and includes a bearer token, `child_ident` for
the child.  The child process should present `child_ident`  to the server
in a `child_attach` RPC in order to attach to the cloned file descriptor table.

```
Header:
    u32         status      0
    u32         body_size   8
Body:
    u64         child_ident
```


`child_attach`
--------------

### Request

```
Header:
    u32         op_code     8
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

-
-
-
-
-


