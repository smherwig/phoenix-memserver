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

- 
-
-
-
-


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

-
-
-


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


`new_fdtable`
-------------

### Request

```
Header:
    u32         op_code     6
    u32         body_size   0
```

### Response


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

-
-
-
-
-


