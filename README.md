Overview
========
The sm-vericrypt-basic and sm-vericrypt memory servers for the
[Phoenix](https://github.com/smherwig/phoenix) SGX microkernel.

Note that, internally, smdish is sm-vericrypt-basic, and smuf is sm-vericrypt.
The Phoenix source also has a built-in shared memory implementation called
sm-crypt that does not use a server (within the Phoenix source, it is referred
to as smc).

In the shared memory filesystems, files are called *memory files*, and either
represent a pure, content-less lock, or a lock with an associated shared memory
segment.  Memory files are non-persistent: they are created on the first open
and destroyed when no process holds a descriptor to the file and no process has
the associated memory segement mapped.

All three shared memory implementations store a master copy of the shared
memory segment at a known location (either a particular server or file).  Upon
locking a file, the client "downloads" the master copy and updates its internal
memory maps.  On unlock, the client copies its copy to the master.

- **sm-vericrypt-basic** uses an enclaved server to keep the canonical memory
files in an in-enclave red-black tree.
- **sm-vericrypt** implements a memory file as two untrusted host files: a
mandatory lock file, and an optional segment file.  The segment file is
encrypted with AES-256-GCM, and the smc-vericrypt server maintains an
in-enclave, shadowed copy of the lockfile.
- **sm-crypt** is similar to sm-vericrypt, but assumes the untrusted host does
not tamper with data.  As such, sm-crypt uses AES-256-CTR instead of
AES-256-GCM, and does not need an enclaved server to monitor the integrity of
the lockfile or IV.



<a name="building"/> Building
=============================

The memory servers depend on
[librho](https://github.com/smherwig/librho) and
[librpc](https://github.com/smherwig/phoenix-librpc).
I assume that dependencies are installed under `$HOME`; modify the memservers'
Makefile if this is not the case.


To build the sm-vericrypt-basic (smdish) and sm-vericrypt (smuf) memory
servers, enter:

```
cd ~/src
git clone https:///github.com/smherwig/phoenix-memserver memserver
cd memserver/smdish
make
cd ../smuf
make
```

A limitation of sm-vericrypt and sm-crypt is that if the application terminates
before the closing the memory files, Phoenix will not remove the associated
backing host files for the memory segments and locks.  The script
`bin/reset_phoenix_memfiles.sh` may be invoked to clear these files between runs
of Phoenix (assuming these files exist under `~/var/phoenix/memfiles`).

Ensure `$HOME/bin` is on the user's `$PATH`, and install
`reset_phoenix_memfiles.sh`:

```
cp ~/src/memserver/bin/reset_phoenix_memfiles.sh ~/bin/
```

The script is simply invoked as:

```
reset_phoenix_memfiles.sh
```

<a name="packaging"/> Packaging
===============================

I assume that [phoenix](https://github.com/smherwig/phoenix#building) is built
and located at `$HOME/src/phoenix` and that
[makemanifest](https://github.com/smherwig/phoenix-makemanifest) is cloned to
`~/src/makemanifest`.

Copy the keying material:

```
cp ~/share/phoenix/root.crt ~/src/memserver/smdish
cp ~/share/phoenix/proc.crt ~/src/memserver/smdish 
cp ~/share/phoenix/proc.key ~/src/memserver/smdish 

cp ~/share/phoenix/root.crt ~/src/memserver/smuf
cp ~/share/phoenix/proc.crt ~/src/memserver/smuf
cp ~/share/phoenix/proc.key ~/src/memserver/smuf 
```

To package the smdishserver to run in an enclave, enter:

```
cd ~/src/makemanifest
./make_sgx.py -g ~/src/phoenix -k ~/share/phoenix/enclave-key.pem -p ~/src/memserver/deploy/smdishserver.conf -t $PWD -v -o smdishserver
```


To package the smufserver to run in an enclave, enter:

```
cd ~/src/makemanifest
./make_sgx.py -g ~/src/phoenix -k ~/share/phoenix/enclave-key.pem -p ~/src/memserver/deploy/smufserver.conf -t $PWD -v -o smufserver
```


<a name="micro-benchmarks"/> Micro-benchmarks
=============================================

The `smbench` benchmarking tool measures the mean time for a process to
evaluate a critical section (a lock and unlock operation pair) over shared
memory.  We use `smbench` to evaluate the performance of sm-vericrypt-basic,
sm-vericypt, and sm-crypt.  `smbench` always runs in an enclave using exitless
system calls.  For sm-vericrypt-basic and sm-vericrypt, we evaluate the servers
running outside of SGX (*non-SGX*), within SGX (*SGX*), and within SGX with
exitless system calls (*exitless*).

Build `smbench`:

```
cd  ~/src/memserver/bench
make
```


sm-vericrypt-basic (smdish)
---------------------------

Edit `~/src/memserver/bench/smbench.conf` and ensure there is the single 
`MOUNT` directive:

```
MOUNT pipe:2011863273 /memserver0 smdish
```

Package `smbench` to run in an enclave:

```
cd ~/src/makemanifest
./make_sgx.py -g ~/src/phoenix -k ~/share/phoenix/enclave-key.pem -p ~/src/memserver/bench/smbench.conf -t $PWD -v -o smbench
```

### <a name="micro-bench-sm-vericrypt-basic-non-sgx"/> non-SGX

In one terminal, run smdishserver outside of an enclave:

```
cd ~/src/memserver/smdish
./smdishserver -Z root.crt proc.crt proc.key -a /graphene/123456/77ea98e9
```

In a second terminal, run smbench within an enclave:

```
cd ~/src/makemanifest/smbench
./smbench.manifest.sgx  /memserver0/foo /memserver0/foo 1024 10000
```

This command will execute 10,000 critical sections that lock and unlock a
1024-byte shared memory segment called `foo`.


### <a name="micro-bench-sm-vericrypt-basic-sgx"/> SGX

Ensure that `~/src/memserver/deploy/smdishserver.conf` has the directive:

```
THREADS 1
```

Package smdishserver to run in an enclave:

```
cd ~/src/makemanifest
./make_sgx.py -g ~/src/phoenix -k ~/share/phoenix/enclave-key.pem -p ~/src/memserver/deploy/smdishserver.conf -t $PWD -v -o smdishserver
```

In one terminal, run smdishserver in an enclave:

```
cd ~/src/makemanifest/smdishserver
./smdishserver.manifest.sgx -Z /srv/root.crt /srv/proc.crt /srv/proc.key /etc/ramones
```

In a second terminal, run smbench in an enclave:

```
cd ~/src/makemanifest/smbench
./smbenchmanifest.sgx  /memserver0/foo /memserver0/foo 1024 10000
```


### <a name="micro-bench-sm-vericrypt-basic-exitless"/> exitless

Ensure that `~/src/memeserver/deploy/smdishserver.conf` has the directive:

```
THREADS 1 exitless
```

Otherwise, repeat as with the the [SGX](#micro-bench-sm-vericrypt-basic-sgx) case.



sm-vericrypt (smuf)
-------------------

Edit `~/src/memserver/bench/smbench.conf` and ensure there is the single
`MOUNT` directive:

```
MOUNT pipe:2011863273,file:$HOME/var/phoenix/memfiles/0 /memserver0,/memfiles0 smuf
```

Package `smbench` to run in an enclave:

```
cd ~/src/makemanifest
./make_sgx.py -g ~/src/phoenix -k ~/share/phoenix/enclave-key.pem -p ~/src/memserver/bench/smbench.conf -t $PWD -v -o smbench
```


### <a name="micro-bench-sm-vericrypt-non-sgx"/> non-SGX

In one terminal, run smufserver outside of an enclave:

```
reset_phoenix_memfiles.sh
cd ~/src/memserver/smuf
./smufserver -Z root.crt proc.crt proc.key -r $HOME/var/phoenix/memfiles/0 -a /graphene/123456/77ea98e9
```

In a second terminal, run smbench within an enclave:

```
cd ~/src/makemanifest/smbench
./smbench.manifest.sgx  /memserver0/foo /memserver0/foo 1024 10000
```


### <a name="micro-bench-sm-vericrypt-sgx"/> SGX

Ensure that `~/src/memeserver/deploy/smufserver.conf` has the directive:

```
THREADS 1
```

Package smufserver to run in an enclave:

```
cd ~/src/makemanifest
./make_sgx.py -g ~/src/phoenix -k ~/share/phoenix/enclave-key.pem -p ~/src/memserver/deploy/smufserver.conf -t $PWD -v -o smufserver
```

In one terminal, run sm-vericrypt in an enclave:

```
reset_phoenix_memfiles.sh
./smufserver.manifest.sgx -Z /srv/root.crt /srv/proc.crt /srv/proc.key -r /memfiles0 /etc/ramones
```

In a second terminal, run smbench in an enclave:

```
cd ~/src/makemanifest/smdish
./smdish.manifest.sgx  /memserver0/foo /memserver0/foo 1024 10000
```


### <a name="micro-bench-sm-vericrypt-exitless"/> exitless

Ensure that `~/src/memeserver/deploy/smufserver.conf` has the directive:

```
THREADS 1 exitless
```

Otherwise, repeat as with the the [SGX](#micro-bench-sm-vericrypt-sgx) case.


sm-crypt
--------

