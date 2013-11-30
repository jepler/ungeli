# ungeli

I recently started using geli-encrypted devices for offsite backups.
However, I worry that in the event of a disaster I'm more likely to
have a Linux machine on hand than a (k)FreeBSD machine, so I'd like
to be able to read my backups.

To that end, I've written a Python program to extract the master key
from a geli metadata block (geli-extract-mkey.py), and a C / openssl
program which will decrypt blocks given the master key, optionally
serving it as a block device via nbd on Linux.

These utilities have only been tested on a toy-sized AES-128-XTS
volume that uses a password and no keyfiles.  This is the only
supported cipher type, and authentication is not supported.  Only
blocksize 4096 has been tested, and files less than 2^20 blocks
(requiring multiple keys) also have not been tested.

## Requirements

 * Gnu99-compatible C compiler (tested with gcc 4.8)
 * OpenSSL (recent version required for AES-128-XTS) (tested with 1.0.1e)
 * Python interpreter (tested with Python 2.7)
 * [PyCrypto][pc] (tested with 2.6.1)
 * Optional: Linux (for network block device support)

 [pc]: https://www.dlitz.net/software/pycrypto/

## Usage

The volumes I've tested this on so far are created with nearly-default
parameters:
    geli init -s 4096 -J geli-password block-device
which gives AES-128-XTR encryption and no authentication.  This is
probably the only type of volume that will work.

Edit geli-extract-mkey.py to change the volume, password (and, in
theory, keyfiles), and run.  It can take upwards of a minute to run
the Python pkcsv2 algorithm, so I've hardcoded its output for the
geli-test volume.  Record the hex-format master key which is printed:

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

You can also serve the decrypted contents via a network block device:

    $ sudo ./ungeli -m 3f6d1fc8... geli-test /dev/nbd0 &
    $ dd if=/dev/nbd0 bs=4096 count=2
                        GNU GENERAL PUBLIC LICENSE
                           Version 3, 29 June 2007

     Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
    ...

If that volume happens to be a compatible zpool then you can mount it
with zfsonlinux as readonly:

    $ sudo ./ungeli -m 3f6d1fc8... geli-test /dev/nbd0 &
    $ sudo zpool import -d /dev -o readonly=on npool
    $ cat /npool/example/GPL-3
                        GNU GENERAL PUBLIC LICENSE
                           Version 3, 29 June 2007

     Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
    ...

## License

Copyright © 2013 Jeff Epler <jepler@unpythonic.net>

GPLv3+ with OpenSSL linking exception

When compiled and linked "This product includes software developed by the
OpenSSL Project for use in the OpenSSL Toolkit (http://www.openssl.org/)".
