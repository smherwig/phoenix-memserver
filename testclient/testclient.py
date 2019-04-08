#!/usr/bin/env python

import errno
import getopt
import os
import shlex
import sys

import mdish

# TODO:
#   add readline support

_SIZEOF_SUN_PATH = 108

_USAGE = """
usage: testclient [options] UDSPATH
  options:
    -a
        Treat UDSPATH as an abstract socket (adds a nul byte)

    -h
        Show this help message and exit
    
    -r,--cacert CACERT
        CA certificate file

    -c,--cert CERT
        Client cretificate

    -k,--key KEYFILE
        Private key file

  args:
    UDSPATH
        The path to the UNIX domain socket to connect to

If all of (cacert, cert, key) is omitted, the client does
not use SSL.

If any of (cacert, cert, key) is given, then all three must
be provided, and the client uses SSL.
""".strip()

def _warn(fmt, *args):
    fmt = '[warn] %s' % fmt
    if not fmt.endswith('\n'):
        fmt += '\n'
    sys.stdout.write(fmt % args)

def _usage(exitcode):
    sys.stderr.write('%s\n' % _USAGE)
    sys.exit(exitcode)

def _create_udspath(udspath, anonymous):
    pathlen = len(udspath)
    if anonymous:
        frontpad = '\x00'
        backpad = '\x00' * (_SIZEOF_SUN_PATH - pathlen - 1)
    else:
        frontpad = ''
        # Python will add an extra nul-byte for non-anonymous
        # unix socket paths, hence the  - 1
        backpad = '\x00' * (_SIZEOF_SUN_PATH - pathlen - 1)
    path = frontpad + udspath + backpad
    print 'len=%d, path="%s"' % (len(path), path)
    return path

def _parse_int(s, tag):
    try:
        i = int(s)
    except ValueError:
        raise ValueError(tag)
    else:
        return i

def _file_open_proxy(client, args):
    name = args[0]
    fd = client.file_open(name)
    return fd

def _file_close_proxy(client, args):
    fd = _parse_int(args[0], 'close: fd must be an int')
    error = client.file_close(fd)
    return error

def _file_advlock_proxy(client, args):
    fd = _parse_int(args[0], 'lock: fd must be an int')
    lockop = _parse_int(args[1], 'lock: lockop must be an int')
    error = client.file_advlock(fd, lockop)
    return error

def _mmap_proxy(client, args):
    fd = _parse_int(args[0], 'mmap: fd must be an int')
    size = _parse_int(args[1], 'mmap: size must be an int')
    error = client.mmap(fd, size)
    return fd

# TOOD: POSTPONE
def _munmap_proxy(client, args):
    pass

def _fork_proxy(client, args):
    ident = client.fork()
    return ident

def _child_attach_proxy(client, args):
    ident = _parse_int(args[0], 'child_attach: ident must be an int')
    error = client.child_attach(ident)
    return error

def _new_fdtable_proxy(client, args):
    error = client.new_fdtable()
    return error

def _shmwrite_proxy(client, args):
    data = args[0]
    client.shmwrite(data)

def _shmread_proxy(client, args):
    n = _parse_int(args[0], 'shmread: n must be an int')
    return client.shmread(n)

def _shmseek_proxy(client, args):
    i = _parse_int(args[0], 'shmseek: i must be an int')
    return client.shmseek(i)

_HELP = """
file_open <name>
file_close <fd>
file_advlock <fd> <1 (lock) | 2 (unlock)>
mmap <fd> <size>
munmap (NOT IMPLEMENTED)
fork
child_attach <id>
new_fdtable

shmwrite <data>
smhread  <nbytes>
shmseek <pos>
""".strip()

def _help(client, args):
    print _HELP

_cmdtable = {
    # cmd             func              nargs
    'file_open':    (_file_open_proxy,      1),
    'file_close':   (_file_close_proxy,     1),
    'file_advlock': (_file_advlock_proxy,   2),
    'mmap':         (_mmap_proxy,           2),
    'munmap':       (_munmap_proxy,         1),
    'fork':         (_fork_proxy,           0),
    'child_attach': (_child_attach_proxy,   1),
    'new_fdtable':  (_new_fdtable_proxy,    0),
    # local
    'shmwrite':  (_shmwrite_proxy, 1),
    'shmread':   (_shmread_proxy,  1),
    'shmseek':   (_shmseek_proxy,  1),
    '?'      :   (_help,           0),
}

def _fscall(client, cmd, args): 
    if cmd not in _cmdtable:
        _warn("'%s' not a valid command\n" % cmd)
        return
    
    fn, nargs = _cmdtable[cmd]
    if len(args) != nargs:
        _warn("'%s' takes %d args; %d provided" % \
                (cmd, nargs, len(args)))
        return

    try:
        ret = fn(client, args)
    except (ValueError, mdish.MDISHError) as err:
        _warn(str(err))
        return
    print ret 

def _cmdloop(client):
    while True:
        # CTRL-D => EOFError
        # CTRL-C => KeyboardInterrupt
        try:
            cmdline = raw_input('> ')
        except (EOFError, KeyboardInterrupt) as err:
            client.disconnect()
            sys.exit(0)
        args = shlex.split(cmdline)
        if not args:
            continue
        cmd = args.pop(0)
        _fscall(client, cmd, args)

def main(argv):
    shortopts = 'ahr:c:k:'
    longopts = ['anonymous', 'help', 'cacert=', 'cert=', 'privkey=']
    # options
    anonymous = False
    cacert = None
    cert = None
    privkey = None

    try:
        opts, args = getopt.getopt(argv[1:], shortopts, longopts)
    except getopt.GetoptError as err:
        sys.stderr.write('%s\n', str(err))
        _usage(1)

    for o, a in opts:
        if o in ('-a', '--anonymous'):
            anonymous = True
        elif o in ('-h', '--help'):
            _usage(0)
        elif o in ('-r', '--cacert'):
            cacert = a
        elif o in ('-c', '--cert'):
            cert = a
        elif o in ('-k', '--privkey'):
            privkey = a
        else:
            assert False, "unhandled option '%s'" % o

    if len(args) != 1:
        _usage(1)

    udspath = args[0]
    udspath = _create_udspath(udspath, anonymous)

    sslinfo = [cacert, cert, privkey]
    if any(sslinfo) and not all(sslinfo):
        _usage(1)

    client = mdish.MDISHClient(udspath, cacert, cert, privkey, verbose=True)
    client.connect()
    _cmdloop(client)

if __name__ == '__main__':
    main(sys.argv)
