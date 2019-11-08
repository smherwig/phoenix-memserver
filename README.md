Overview
========
The sm-vericrypt-basic and sm-vericrypt memory servers for the
[Phoenix](https://github.com/smherwig/phoenix) SGX microkernel.

Note that, internally, smdish is sm-vericrypt-basic, smuf is sm-vericrypt.  The
Phoenix source also has a built-in shared memory called sm-crypt that does not
use a server (within the Phoenix source, it is referred to as smc).

In the shared memory filesystems, files are called *memory files*, and either
represent a pure, content-less lock, or a lock with an associated shared memory
segment.  Memory files are non-persistent: they are created on the first open
and destroyed when no process holds a descriptor to the file and no process has
the associated memory segement mapped.

All three share memory implementations store a master copy of the shared
memory segment at a known location (either a particular server or file).  Upon
locking a file, the client "downloads" the master copy and updates its internal
memory maps.  On unlock, the client copies its replica to the master.

- **sm-vericrypt-basic** uses an enclaved server to keep the canonical memory
files in an in-enclave red-black tree.
- **sm-vericrypt** implements a memory file as two untrusted host files: a
mandatory lock file, and an optional segment file.  The segment file is
encrypted with AES-256-GCM, and the smc-vericrypt server maintains an
in-enclave, shadowed copy of the lockfile.
- **sm-crypt** is similar to sm-verictyp, but assumes the untrusted host does
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

A limitation of sm-vericrypt and sm-crypt is that they do not remove the
backing host files for the memory segments and locks when Phoenix terminates.
The script `bin/reset_phoenix_memdirs.sh` clears these files 
between runs of Phoenix (assuming these files exist under ~/var/phoenix/memfiles`).

Ensure `$HOME/bin` is on the user's `$PATH`, and install
`reset_phoenix_memdirs.sh`:

```
cp ~/src/memserver/bin/reset_phoenix_memdirs.sh ~/bin/
```

The script is simply invoked as:

```
reset_phoenix_memdirs.sh
```

<a name="packaging"/> Packaging
===============================

I assume that [phoenix](https://github.com/smherwig/phoenix#building) is built
and that [makemanifest](https://github.com/smherwig/phoenix-makemanifest) has
been cloned to `~/src/makemanifest`:

Copy the keying material:

```
cp ~/share/phoenix/root.crt ~/src/memserver/smdish
cp ~/share/phoenix/proc.crt ~/src/memserver/smdish 
cp ~/share/phoenix/proc.key ~/src/memserver/smdish 

cp ~/share/phoenix/root.crt ~/src/memserver/smuf
cp ~/share/phoenix/proc.crt ~/src/memserver/smuf
cp ~/share/phoenix/proc.key ~/src/memserver/smuf 
```

smdish
------

Package the smdishserver:

```
cd ~/src/makemanifest
./make_sgx.py -g ~/src/phoenix -k ~/share/phoenix/enclave-key.pem -p ~/src/memserver/deploy/smdishserver.conf -t $PWD -v -o smdishserver
```


smuf
----

Package the smufserver:

```
cd ~/src/makemanifest
./make_sgx.py -g ~/src/phoenix -k ~/share/phoenix/enclave-key.pem -p ~/src/memserver/deploy/smufserver.conf -t $PWD -v -o smufserver
```


<a name="micro-benchmarks"/> Micro-benchmarks
=============================================

The `smbench` benchmarking tool measures the mean time for a process to
evaluate a critical section (a lock and unlock operation pair) over shared
memory.


```
cd  ~/src/memserver/bench
make
```

```
./make_sgx.py -g ~/src/phoenix -k ~/share/phoenix/enclave-key.pem -p ~/src/memserver/bench/smbench.conf -t $PWD -v -o smbench
```

```
# outside of sgx
./smufserver -Z root.crt proc.crt proc.key -r $HOME/var/phoenix/memfiles/0 -a /graphene/123456/77ea98e9
```

```
# inside of sgx
./smufserver.manifest.sgx -Z /srv/root.crt /srv/proc.crt /srv/proc.key -r /memfiles0 /etc/ramones
```
