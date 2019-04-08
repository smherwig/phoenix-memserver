import binascii
import os
import socket
import ssl
import StringIO
import struct
import sys
import time

# TODO:
#  For now, the purpose of this module is for a basic
#  testing.  As such, there are a few simplifications/limitations:
#
#  - All network calls are blocking.  In the future, we
#    might want to allow non-blocking I/O.
#
#  - A client can only have one shared memory segment.

_MDISH_OP_FILE_OPEN     = 0
_MDISH_OP_FILE_CLOSE    = 1
_MDISH_OP_FILE_ADVLOCK  = 2
_MDISH_OP_MMAP          = 3
_MDISH_OP_MUNMAP        = 4
_MDISH_OP_FORK          = 5
_MDISH_OP_CHILD_ATTACH  = 6
_MDISH_OP_NEW_FDTABLE   = 7

_MDISH_LOCKOP_LOCK      = 1
_MDISH_LOCKOP_UNLOCK    = 2

_MDISH_ERPC = 999

def _pp_hexlify(buf):
    b = binascii.hexlify(buf)
    w = []
    for i in xrange(0, len(b), 4):
        w.append(b[i: i+4])
    return ' '.join(w)

# We used a fixed-size buffer to simulate the shared memory
class FixedBuffer:
    def __init__(self, size):
        self.size = size
        self.segment = StringIO.StringIO()
    
    def write(self, data):
        datalen = len(data)
        offset = self.segment.tell()
        if (offset + datalen) > self.size:
            return ValueError('write would overrun fixed buffer')
        self.segment.write(data)

    def read(self, n):
        offset = self.segment.tell()
        if (offset + n) > self.size:
            return ValueError('read would overrun fixed buffer')
        return self.segment.read(n)

    def seek(self, i):
        if i < 0 or i >= self.size:
            return ValueError('seek would go outside of end of buffer')
        self.segment.seek(i, os.SEEK_SET)

    def getvalue(self):
        return self.segment.getvalue()

class MDISHError(OSError):
    def __init__(self, errnoval, filename=None):
        if errnoval == _MDISH_ERPC:
            msg = 'mdish RPC error'
        else:
            msg = os.strerror(errnoval)
        if filename:     
            OSError.__init__(self, errnoval, msg, filename)
        else:
            OSError.__init__(self, errnoval, msg)

class MDISHClient:
    def __init__(self, udspath, cacert=None, cert=None, privkey=None,
            verbose=False):
        self.udspath = udspath
        self.cacert = cacert
        self.cert = cert
        self.privkey = privkey
        self.verbose = verbose

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) 
        # we simulate the shared memory pages
        self.shm = None

    def _debug(self, fmt, *args):
        if self.verbose:
            fmt = '[debug] %s' % fmt
            if not fmt.endswith('\n'):
                fmt += '\n'
            sys.stdout.write(fmt % args)

    def _recvn(self, want):
        self._debug('want %d bytes' % want)
        need = want
        b = ''
        while need:
            b += self.sock.recv(need)
            need = want - len(b)
        self._debug('got %d bytes' % len(b))
        return b

    def _marshal_str(self, s):
        slen = len(s)
        fmt = '>I%ds' % slen
        b = struct.pack(fmt, slen, s)
        return b

    def _marshal_cbuf(self, buf):
        buflen = len(buf)
        fmt = '>I%ds' % buflen
        b = struct.pack(fmt, buflen, buf)
        return b

    def _marshal_hdr(self, op, bodylen):
        return struct.pack('>II', op, bodylen)

    def _demarshal_hdr(self, resphdr):
        return struct.unpack('>II', resphdr)

    def _request(self, req):
        #self._debug('raw request: %s', _pp_hexlify(req));
        start_time = time.clock()
        self.sock.sendall(req)
        resphdr = self._recvn(8)
        status, bodylen = self._demarshal_hdr(resphdr)
        body = ''
        if bodylen:
            body = self._recvn(bodylen)
        end_time = time.clock()
        self._debug('latency: %f secs', end_time - start_time)
        #self._debug('raw response: %s', _pp_hexlify(resphdr + body))
        #self._debug('parsed response: status=%d, bodylen=%d, body=%s',
        #        status, bodylen, _pp_hexlify(body))
        self._debug('parsed response: status=%d, bodylen=%d', status, bodylen)
        return (status, body)

    def file_open(self, name):
        body = self._marshal_str(name)
        header = self._marshal_hdr(_MDISH_OP_FILE_OPEN, len(body))
        req = header + body
        error, respbody = self._request(req)
        if error != 0:
            assert respbody == ''
            raise MDISHError(error, name)
        assert len(respbody) == 4
        fd = struct.unpack('>I', respbody)[0]
        return fd

    def file_close(self, fd):
        body = struct.pack('>I', fd)
        header = self._marshal_hdr(_MDISH_OP_FILE_CLOSE, len(body))
        req = header + body
        error, respbody = self._request(req)
        assert respbody == ''
        if error != 0:
            raise MDISHError(error)
        return error    # TODO: make this a void function?

    def file_advlock(self, fd, lockop):
        if lockop == _MDISH_LOCKOP_LOCK:
            return self._lock(fd)
        elif lockop == _MDISH_LOCKOP_UNLOCK:
            return self._unlock(fd)
        else:
            raise ValueError('lockop must be 1 or 2')

    def _lock(self, fd):
        body = struct.pack('>II', fd, _MDISH_LOCKOP_LOCK)
        header = self._marshal_hdr(_MDISH_OP_FILE_ADVLOCK, len(body))
        req = header + body
        error, respbody = self._request(req)
        if error != 0:
            assert respbody == ''
            raise MDISHError(error)
        if self.shm and respbody:
            self.shm.seek(0)
            self.shm.write(respbody)
        return error    # TODO: make this a void function?

    def _unlock(self, fd):
        if self.shm:
            mem = self.shm.getvalue()
            fmt = '>II%ds' % self.shm.size
            body = struct.pack(fmt, fd, _MDISH_LOCKOP_UNLOCK, mem)
        else:
            body = struct.pack(fmt, fd, _MDISH_LOCKOP_UNLOCK)
        header = self._marshal_hdr(_MDISH_OP_FILE_ADVLOCK, len(body))
        req = header + body
        error, respbody = self._request(req)
        assert respbody == ''
        if error != 0:
            raise MDISHError(error)
        return error    # TODO: make this a void function?

    def mmap(self, fd, size):
        body = struct.pack('>II', fd, size)
        header = self._marshal_hdr(_MDISH_OP_MMAP, len(body))
        req = header + body
        error, respbody = self._request(req)
        if error != 0:
            raise MDISHError(error)
        assert len(respbody) == 4
        self.shm = FixedBuffer(size)
        sd = struct.unpack('>I', respbody)[0]
        return sd

    # TODO: POSTPONE
    def munmap(self, fd, offset, count):
        body = struct.pack('>III', fd, offset, count)
        header = self._marshal_hdr(_MDISH_OP_FILE_CLOSE, len(body))
        req = header + body
        error, respbody = self._request(req)
        if error != 0:
            assert respbody == ''
            raise MDISHError(error)
        return respbody

    def fork(self):
        req = self._marshal_hdr(_MDISH_OP_FORK, 0)
        error, respbody = self._request(req)
        if error != 0:
            assert respbody == ''
            raise MDISHError(error)
        assert len(respbody) == 8
        ident = struct.unpack('>Q', respbody)[0]
        return ident

    def child_attach(self, ident):
        body = struct.pack('>Q', ident)
        bodylen = len(body)
        header = self._marshal_hdr(_MDISH_OP_CHILD_ATTACH, bodylen)
        req = header + body
        error, respbody = self._request(req)
        assert respbody == ''
        if error != 0:
            raise MIDSHError(error)
        # FIXME: shouldn't hardcode; the mapping entry would be inherited
        # from graphene parent as part of the fork.
        self.shm = FixedBuffer(100)
        return error

    def new_fdtable(self):
        req = self._marshal_hdr(_MDISH_OP_NEW_FDTABLE, 0)
        error, respbody = self._request(req)
        assert respbody == ''
        if error != 0:
            raise MDISHError(error)
        return error

    ########################################## 
    # local (i.e., not RPCs)
    ###########################################

    def shmwrite(self, data):
        self.shm.write(data)

    def shmread(self, n):
        return self.shm.read(n)

    def shmseek(self, i):
        self.shm.seek(i)

    def connect(self):
        self.sock.connect(self.udspath) 
        if self.cert:
            self.sock = ssl.wrap_socket(
                    self.sock,
                    keyfile=self.privkey,
                    certfile=self.cert,
                    server_side=False,
                    cert_reqs=ssl.CERT_REQUIRED,
                    ca_certs=self.cacert,
                    ssl_version=ssl.PROTOCOL_TLSv1_2,
                    do_handshake_on_connect=False)
            self.sock.do_handshake()


    def disconnect(self):
        self.sock.close()
