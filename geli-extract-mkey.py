#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright © 2013 Jeff Epler <jepler@unpythonic.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import Crypto.Cipher.AES as AES
import hashlib
import itertools
import struct

CRYPTO_AES_XTS     = 22

SHA512_MDLEN       = 64

G_ELI_SALTLEN      = 64
G_ELI_MAXKEYLEN    = 64
G_ELI_MAXMKEYS     =  2        
G_ELI_DATAKEYLEN   = G_ELI_MAXKEYLEN
G_ELI_USERKEYLEN   = G_ELI_MAXKEYLEN
G_ELI_IVKEYLEN     = G_ELI_MAXKEYLEN
G_ELI_DATAIVKEYLEN = (G_ELI_DATAKEYLEN + G_ELI_IVKEYLEN)
G_ELI_MKEYLEN      = (G_ELI_DATAIVKEYLEN + SHA512_MDLEN)

AES_XTS_BLOCKSIZE  = 16
AES_XTS_ALPHA      = 0x87

def nfromf(s):
    sz = struct.calcsize(s)
    return len(struct.unpack(s, '\0' * sz))

def stake(it, s):
    n = nfromf(s)
    if n == 1:
        return it.next()
    elif s[-1] in "cs":
        return "".join(it.next() for i in range(n))
    else:
        return tuple(it.next() for i in range(n))

def flatten(s):
    r = []
    for i in s:
        if isinstance(i, (list, tuple, str)): 
            r.extend(i)
        else:
            r.append(i)
    return r

class Struct(object):
    _byteorder_ = ""
    def __init__(self, *args):
        if len(args) != len(self._fields_):
            raise TypeError, "%s() takes %d arguments (%d given)" % (
                type(self).__name__, len(self._fields_), len(args))
        for n, a in zip(self._fields_, args):
            setattr(self, n[0], a)

    @classmethod
    def formatstring(cls):
        return cls._byteorder_ + "".join(n[1] for n in cls._fields_)

    @classmethod
    def size(cls):
        return struct.calcsize(cls.formatstring())

    @classmethod
    def fromstring(cls, s):
        data = iter(struct.unpack(cls.formatstring(), s))
        args = [stake(data, n[1]) for n in cls._fields_]
        return cls(*args)

    def topackargs(self):
        return flatten(getattr(self, n[0]) for n in self._fields_)

    def tostring(self):
        return struct.pack(self.formatstring(), *self.topackargs())

def read_at_offset(f, count, offset, whence=0):
    f.seek(offset, whence)
    return f.read(count)

def xorbuf(a, b):
    return "".join(chr(ord(ac) ^ ord(bc)) for ac, bc in zip(a, b))

class EliCryptoHmac:
    def __init__(self, hkey=None):
        key = '\0' * 128
        if not hkey:
            pass
        elif len(hkey) <= 128:
            key = (hkey + key)[:128]
        else:
            key = hashlib.sha512(hkey).digest()

        k_ipad = xorbuf(key, '\x36' * 128)
        self.k_opad = xorbuf(key, '\x5c' * 128)

        self.ctx = hashlib.sha512(k_ipad)

    def update(self, s):
        self.ctx.update(s)
        return self

    def final(self, size=None):
        digest = self.ctx.digest()
        lctx = hashlib.sha512()
        lctx.update(self.k_opad)
        lctx.update(digest)
        return lctx.digest()[:size or SHA512_MDLEN]

def eli_crypto_hmac(k, s, sz=None):
    return EliCryptoHmac(k).update(s).final(sz)

def eli_pkcs5v2_genkey(keylen, salt, passphrase, iterations):
    result = []
    for count in itertools.count(1):
        saltcount = salt + struct.pack(">I", count)
        bsize = min(keylen, SHA512_MDLEN)
        keylen -= bsize

        md = eli_crypto_hmac(passphrase, saltcount)
        keyp = md
        for count in range(1, iterations):
            md = eli_crypto_hmac(passphrase, md)
            keyp = xorbuf(keyp, md)
        result.append(keyp)
        if keylen == 0: break

    return "".join(result)

def eli_mkey_verify(mkey, key):
    hmkey = eli_crypto_hmac(key[:G_ELI_USERKEYLEN], "\0")
    chmac = eli_crypto_hmac(hmkey, mkey[:G_ELI_DATAIVKEYLEN])
    odhmac = mkey[G_ELI_DATAIVKEYLEN:G_ELI_DATAIVKEYLEN+SHA512_MDLEN]
    print "eli_mkey_verify"
    print "hmkey ", hmkey.encode("hex")
    print "chmac ", chmac.encode("hex")
    print "odhmac", odhmac.encode("hex")
    return chmac == odhmac

def eli_crypto_decrypt(algo, data, key):
    print data.encode("hex"), len(data)
    print key.encode("hex"), len(key)
    assert algo == CRYPTO_AES_XTS
    return AES.new(key, AES.MODE_CBC, '\0'*16).decrypt(data)

class EliMetadata(Struct):
    _byteorder_ = "<"
    _fields_ = (
        ("md_magic",       'c' * 16),
        ("md_version",     'I'),
        ("md_flags",       'I'),
        ("md_ealgo",       'H'),
        ("md_keylen",      'H'),
        ("md_aalgo",       'H'),
        ("md_provisize",   'Q'),
        ("md_sectorsize",  'I'),
        ("md_keys",        'B'),
        ("md_iterations",  'i'),
        ("md_salt",        'c' * G_ELI_SALTLEN),
        ("md_mkeys",       'c' * (G_ELI_MAXMKEYS * G_ELI_MKEYLEN)),
        ("md_hash",        'c' * 16)
    )

    @classmethod
    def fromfile(cls, f):
        return cls.fromstring(read_at_offset(f, 511, -512, 2))

    def verify_signature(self):
        return self.md_magic == 'GEOM::ELI\x00\x00\x00\x00\x00\x00\x00'

    def calc_md_hash(self):
        s = self.tostring()
        return hashlib.md5(s[:-16]).digest()

    def verify_hash(self):
        return self.calc_md_hash() == self.md_hash

    def verify_metadata(self):
        return self.verify_signature() and self.verify_hash()

    def mkey_decrypt(self, key):
        enckey = eli_crypto_hmac(key, "\1")
        for nkey in range(G_ELI_MAXMKEYS):
            moff = nkey & G_ELI_MKEYLEN
            bit = 1<<nkey
            if not self.md_keys & bit: continue
            tmpmkey = eli_crypto_decrypt(self.md_ealgo,
                self.md_mkeys[moff:moff+G_ELI_MKEYLEN],
                enckey[:self.md_keylen/8])
            if eli_mkey_verify(tmpmkey, key):
                return tmpmkey

    def genkey(self, passphrase=None, dkey=None, keys=[]):
        ctx = EliCryptoHmac()
        for f in keys:
            ctx.update(f)
        if passphrase or dkey:
            if self.md_iterations == 0:
                ctx.update(self.md_salt)
                ctx.update(passphrase)
            else:
                if not dkey:
                    dkey = eli_pkcs5v2_genkey(SHA512_MDLEN,
                        self.md_salt, passphrase, self.md_iterations)
                print "dkey =", dkey.encode("hex")
                ctx.update(dkey)
        key = ctx.final()
        return key

    def decrypt_master_key(self, passphrase=None, dkey=None, keys=[]):
        key = self.genkey(passphrase, dkey, keys)
        mkey = self.mkey_decrypt(key)
        return mkey

hmac_test_hkey = "\1"
hmac_test_data = "bluemoon"
hmac_test_result = (
    "c2bb740c5c718cc30baccd240af3ef853f872d5a642e0b52449921bdf10723e6"
    "b6e99cbea89bd2da76fb45b8f073f27cc8c9a68c698ac4d51244df74aa13cdc1"
    .decode("hex"))

pkcs_test_hkey = hmac_test_hkey
pkcs_test_passphrase = hmac_test_data
pkcs_test_iterations = 8
pkcs_test_result = (
    "629e270fe754fb70ce2b2e6bc0de923a0f66ec0d41c03dab6b9049c7446e9d12"
    "b154f53cd6bc3f32c37436c7c40293e21ea299dfc6617b8e0315b634b0f8474c"
    .decode("hex"))

def test_eli_crypto_hmac():
    assert eli_crypto_hmac(hmac_test_hkey, hmac_test_data) == hmac_test_result

def test_pkcs5v2():
    assert eli_pkcs5v2_genkey(SHA512_MDLEN, pkcs_test_hkey,
        pkcs_test_passphrase, pkcs_test_iterations) == pkcs_test_result

def main():
    test_eli_crypto_hmac()
    test_pkcs5v2()
    assert EliMetadata.size() == 511

    f = open("geli-test", "rb")
    global md
    md = EliMetadata.fromfile(f)

    # Python pkcs5v2 is mind-numbingly slow..
    dkey = ('132db49996dd263ca40579394bb32bc60cac8b136d14a679838da2c394580762'
            '2a17d0210271f87f735ce1255064049ef3cf593c03873b8f88ff3ea25c283986'
            .decode("hex"))

    #print repr(md.decrypt_master_key("bluemoon"))
    mkey = md.decrypt_master_key(dkey=dkey)
    print "master key is", mkey.encode("hex")

if __name__ == '__main__': main()
