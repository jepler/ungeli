/*  Copyright © 2013 Jeff Epler <jepler@unpythonic.net>
 * 
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 *
 *  When compiled and linked "This product includes software developed by the
 *  OpenSSL Project for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 */
#include <fcntl.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#define IVSIZE (16)
#define SHA512_MDLEN (SHA512_DIGEST_LENGTH)
#define ELI_MAXKEYLEN (64)
#define ELI_KEY_SHIFT (20)

static unsigned blocksize = 4096;
static unsigned long long offset = 0;
static unsigned long long nblocks = 1;
static unsigned char mkey[192];

static int
hexcharvalue(char c) {
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static void bintohex(char *dst, const unsigned char *arg, size_t sz)
{
    static char hexletters[16] = "0123456789ABCDEF";
    for(int i=0; i<sz; i++) {
        *dst++ = hexletters[arg[i] >> 4];
        *dst++ = hexletters[arg[i] & 7];
    }
    *dst = 0;
}

static void hextobin(unsigned char *buf, size_t sz, const char *arg)
{
    for(int i=0; i<sz; i++) {
        if(*arg == 0) break;
        unsigned hibit = hexcharvalue(*arg);
        arg++;
        if(*arg == 0) break;
        unsigned lowbit = hexcharvalue(*arg);
        arg++;
        buf[i] = (hibit << 4) | lowbit;
    }
}

static void
set_mkey(const char *arg) {
    hextobin(mkey, sizeof(mkey), arg);
}

static void
perror_fatal(const char *s) __attribute__((noreturn));
static void
perror_fatal(const char *s) {
    perror(s); abort();
}

static void
fatal(const char *s) __attribute__((noreturn));
static void
fatal(const char *s) {
    fprintf(stderr, "%s\n", s); abort();
}

static void
fatalf(const char *fmt, ...) __attribute__((noreturn));
static void
fatalf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    abort();
}

static void
putle64(unsigned char *buf, uint64_t arg)
{
    *buf++ = (arg      ) & 0xff;
    *buf++ = (arg >>  8) & 0xff;
    *buf++ = (arg >> 16) & 0xff;
    *buf++ = (arg >> 24) & 0xff;
    *buf++ = (arg >> 32) & 0xff;
    *buf++ = (arg >> 40) & 0xff;
    *buf++ = (arg >> 48) & 0xff;
    *buf   = (arg >> 56) & 0xff;
}

static void
xtr_ivgen(unsigned char *buf, uint64_t arg) {
    putle64(buf, arg);
    memset(buf+8, 0, 8);
}

static void
read_full(int fd, unsigned char *blk, int blocksize) {
    do {
        int res = read(fd, blk, blocksize);
        if(res == 0) fatal("read_full read() -> 0");
        if(res < 0 && errno == EAGAIN) continue;
        if(res < 0) perror_fatal("read_full");
        blk += res;
        blocksize -= res;
    } while(blocksize);
}

static void
write_full(int fd, const unsigned char *blk, int blocksize) {
    do {
        int res = write(fd, blk, blocksize);
        if(res == 0) fatal("write_full write() -> 0");
        if(res < 0 && errno == EAGAIN) continue;
        if(res < 0) perror_fatal("write_full");
        blk += res;
        blocksize -= res;
    } while(blocksize);
}

typedef struct {
    SHA512_CTX ctx;
    unsigned char k_opad[128];
} eli_crypto_ctx;

static void xorbuf(unsigned char *dest, const unsigned char *src, 
        unsigned char xor, size_t n) {
    for(size_t i=0; i<n; i++) {
        dest[i] = src[i] ^ xor;
    }
}

static void
eli_crypto_ctx_init(eli_crypto_ctx *ctx, 
        const unsigned char *hkey, size_t hkeysz)
{
    unsigned char key[128], k_ipad[128];
    memset(key, 0, sizeof(key));
    if(hkeysz <= 128) {
        memcpy(key, hkey, hkeysz);
    } else {
        SHA512(hkey, hkeysz, key);
    }

    xorbuf(k_ipad, key, 0x36, 128);
    xorbuf(ctx->k_opad, key, 0x5c, 128);
    SHA512_Init(&ctx->ctx);
    SHA512_Update(&ctx->ctx, k_ipad, 128);
}

static void
eli_crypto_ctx_update(eli_crypto_ctx *ctx,
        const unsigned char *data, size_t datasz)
{
    SHA512_Update(&ctx->ctx, data, datasz);
}

static void
eli_crypto_ctx_final(eli_crypto_ctx *ctx,
        unsigned char *out, size_t outsz)
{
    unsigned char digest[SHA512_MDLEN];
    SHA512_Final(digest, &ctx->ctx);
    SHA512_Init(&ctx->ctx);
    SHA512_Update(&ctx->ctx, ctx->k_opad, 128);
    SHA512_Update(&ctx->ctx, digest, SHA512_MDLEN);
    SHA512_Final(digest, &ctx->ctx);
    memcpy(out, digest, outsz ? outsz : SHA512_MDLEN);
}

static void
eli_crypto_hmac(const unsigned char *key, size_t keysz,
        const unsigned char *data, size_t datasz,
        unsigned char *out, size_t outsz)
{
    eli_crypto_ctx ctx;
    eli_crypto_ctx_init(&ctx, key, keysz);
    eli_crypto_ctx_update(&ctx, data, datasz);
    eli_crypto_ctx_final(&ctx, out, outsz);
}

static void
eli_key_fill(const unsigned char *mkey, uint64_t keyno,
        unsigned char *key)
{
    unsigned char buf[12];
    memcpy(buf, "ekey", 4);
    putle64(buf+4, keyno);
    eli_crypto_hmac(mkey, ELI_MAXKEYLEN, buf, sizeof(buf), key, 0);
}

void test_eli_crypto_hmac() {
    unsigned char result[SHA512_MDLEN], xresult[SHA512_MDLEN];
    hextobin(xresult, sizeof(xresult),
        "c2bb740c5c718cc30baccd240af3ef853f872d5a642e0b52449921bdf10723e6"
        "b6e99cbea89bd2da76fb45b8f073f27cc8c9a68c698ac4d51244df74aa13cdc1");

    eli_crypto_hmac((unsigned char*) "\1", 1, (unsigned char*) "bluemoon", 8, result, 0);
    
    char hexresult[2*SHA512_MDLEN+1];
    bintohex(hexresult, result, SHA512_MDLEN);
    fprintf(stderr, "A: %s\n", hexresult);
    bintohex(hexresult, xresult, SHA512_MDLEN);
    fprintf(stderr, "X: %s\n", hexresult);

    if(memcmp(result, xresult, sizeof(xresult))) {
        fatal("test_eli_crypto_hmac()");
    }
}

int main(int argc, char **argv) {
    test_eli_crypto_hmac();

    int opt;
    while((opt = getopt(argc, argv, "o:n:b:m:")) != -1) {
        switch(opt) {
        case 'o': offset = strtoull(optarg, NULL, 0); break;
        case 'n': nblocks = strtoull(optarg, NULL, 0); break;
        case 'b': blocksize = atoi(optarg); break;
        case 'm': set_mkey(optarg);
        }
    }

    argc -= optind-1; argv += optind-1;

    int ifd=0, ofd=1;
    if(argc > 1 && strcmp(argv[1], "-")) {
        ifd = open(argv[1], O_RDONLY);
        if(ifd < 0) perror_fatal("open(input)");
    }
    if(argc > 2 && strcmp(argv[2], "-")) {
        ofd = open(argv[2], O_WRONLY | O_CREAT, 0666);
        if(ofd < 0) perror_fatal("open(outut)");
    }

    if(offset)
        if(lseek(ifd, offset*blocksize, SEEK_SET) < 0)
            perror_fatal("lseek(input)");
    
    for(unsigned long long i=0; i<nblocks; i++)
    {
        uint64_t blockoffset = offset + i;
        uint64_t byteoffset = blockoffset * blocksize;
        unsigned char bkey[ELI_MAXKEYLEN];
        eli_key_fill(mkey, (byteoffset >> ELI_KEY_SHIFT) / blocksize, bkey);

        unsigned char biv[IVSIZE];
        xtr_ivgen(biv, byteoffset);
        
        unsigned char ib[blocksize];
        read_full(ifd, ib, blocksize);

        EVP_CIPHER_CTX ctx;
        EVP_CIPHER_CTX_init(&ctx);
        EVP_DecryptInit_ex(&ctx, EVP_aes_128_xts(), NULL, bkey, biv);
        unsigned char ob[blocksize];
        int out_len, final_out_len;
        EVP_DecryptUpdate(&ctx, ob, &out_len, ib, blocksize);
        EVP_DecryptFinal_ex(&ctx, ob+out_len, &final_out_len);
        EVP_CIPHER_CTX_cleanup(&ctx);
        fprintf(stderr, "out_len=%d final_out_len=%d\n", out_len, final_out_len);
        if((out_len + final_out_len) != blocksize) fatal("EVP final_out_len");
        
        write_full(ofd, ob, blocksize);
    }
    return 0;
}
