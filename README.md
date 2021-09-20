# ungeli

I used to use geli-encrypted devices for offsite backups.
However, I worried that in the event of a disaster I'm more likely to
have a Linux machine on hand than a (k)FreeBSD machine, so I'd like
to be able to read my backups.

To that end, a C / openssl program which will decrypt a volume given
its passphrase or master key in hex, optionally serving it as a
block device via nbd on Linux.

These utilities have only been tested on a toy-sized AES-128-XTS
volume that uses a password and no keyfiles.  This is the only
supported cipher type, and authentication is not supported.  Only
blocksize 4096 has been tested, and files less than 2^20 blocks
(requiring multiple keys) also have not been tested.

# Development status

The author (@jepler) is not actively using or developing this project.
Issues and pull requests are not likely to be acted on.
I would be interested in passing this project to a new maintainer.

## Requirements

 * Gnu99-compatible C compiler (tested with gcc 4.8)
 * OpenSSL (tested with 1.1.1k)
 * Optional: Linux (for network block device support)

 [pc]: https://www.dlitz.net/software/pycrypto/

## Usage

The volumes I've tested this on so far are created with nearly-default
parameters on FreeBSD 9 (metadata version 6):
    geli init -s 4096 -J geli-password block-device
which gives AES-128-XTR encryption and no authentication.  This is
probably the only type of volume that will work.
Now you can decrypt with ungeli:

    $ make
    $ ./ungeli -j geli-password -n 2 geli-test
                        GNU GENERAL PUBLIC LICENSE
                           Version 3, 29 June 2007

     Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
    ...

You can also serve the decrypted contents via a network block device:

    $ sudo ./ungeli -j geli-password geli-test /dev/nbd0 &
    $ dd if=/dev/nbd0 bs=4096 count=2
                        GNU GENERAL PUBLIC LICENSE
                           Version 3, 29 June 2007

     Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
    ...

If that volume happens to be a compatible zpool then you can mount it
with zfsonlinux as readonly:

    $ sudo ./ungeli -j geli-password encrypted-zpool /dev/nbd0 &
    $ sudo zpool import -d /dev -o readonly=on npool
    $ cat /npool/example/GPL-3
                        GNU GENERAL PUBLIC LICENSE
                           Version 3, 29 June 2007

     Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
    ...

## TODO

Possible areas for contribution include:

 * Support for keyfiles
 * Support for additional encryption types
 * Support for authentication
 * Support for write access
 * Refactoring / restructuring existing code to enable any of the above

## License

Copyright © 2013 Jeff Epler <jepler@unpythonic.net>

GPLv3+ with OpenSSL linking exception

When compiled and linked "This product includes software developed by the
OpenSSL Project for use in the OpenSSL Toolkit (http://www.openssl.org/)".
