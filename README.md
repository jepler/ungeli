# ungeli

I recently started using geli-encrypted devices for offsite backups.
However, I worry that in the event of a disaster I'm more likely to
have a Linux machine on hand than a (k)FreeBSD machine, so I'd like
to be able to read my backups.

To that end, I've written a Python program to extract the master key
from a geli metadata block (geli-extract-mkey.py), and a C / openssl
program which will decrypt blocks given the master key.

These utilities have only been tested on a toy-sized AES-128-XTS
volume that uses a password and no keyfiles.  This is the only
supported cipher type, and authentication is not supported.

Future directions would include a nbd or fuse filesystem which would
allow the decrypted data to be used as a read-only block device so
that the contained filesystem could actually be mounted and read.

## Requirements

 * Gnu99-compatible C compiler (tested with gcc 4.8)
 * OpenSSL (recent version required for AES-128-XTS) (tested with 1.0.1e)
 * Python interpreter (tested with Python 2.7)
 * [PyCrypto][pc] (tested with 2.6.1)

 [pc]: https://www.dlitz.net/software/pycrypto/

## Usage

Edit geli-extract-mkey.py to change the volume, password (and, in
theory, keyfiles), and run.  It can take upwards of a minute to run
the Python pkcsv2 algorithm.  Record the hex-format key which is
printed:

    $ python geli-extract-mkey.py
    ...
    master key is 3f6d1fc8c02fefd07b55df58f1b29065d2b7b35d5d861fe6509b934737...

Now you can decrypt with ungeli (specify the whole key, the "..."
notation above and below is not magic):

    $ make
    $ ./ungeli -m 3f6d1fc8... -n 2 geli-test
                        GNU GENERAL PUBLIC LICENSE
                           Version 3, 29 June 2007

     Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
    ...

## License

Copyright © 2013 Jeff Epler <jepler@unpythonic.net>

GPLv3+ with OpenSSL linking exception

When compiled and linked "This product includes software developed by the
OpenSSL Project for use in the OpenSSL Toolkit (http://www.openssl.org/)".
