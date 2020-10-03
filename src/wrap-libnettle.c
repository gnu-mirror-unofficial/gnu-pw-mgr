/**
 * @file wrap-libnettle.c
 * 
 *  This file is part of gnu-pw-mgr.
 *
 *  Copyright (C) 2013-2020 Bruce Korb, all rights reserved.
 *  This is free software. It is licensed for use, modification and
 *  redistribution under the terms of the GNU General Public License,
 *  version 3 or later <http://gnu.org/licenses/gpl.html>
 *
 *  gpw is free software: you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  gpw is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *  See the GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
////PULL-HEADERS:

#ifdef HAVE_LIBNETTLE

#include <nettle/pbkdf2.h>

struct dummy_struct {
    unsigned int dummy;
};

#define sha256_ctx            dummy_struct
#define sha256_init_ctx       gpw_init_ctx
#define sha256_process_bytes  gpw_process
#define sha256_finish_ctx     gpw_finish

typedef struct gpw_key_frag gpw_key_frag_t;
struct gpw_key_frag {
    gpw_key_frag_t *    next;
    size_t              size;
    unsigned char       data[0];
};

PVT_static gpw_key_frag_t * data_chain = NULL;
PVT_static gpw_key_frag_t ** next_gpw_key_ptr = &data_chain;

static void
gpw_init_ctx(struct sha256_ctx *ctx)
{
    (void)ctx;
}

static void
gpw_process(const void *buffer, size_t len, struct sha256_ctx *ctx)
{
    size_t sz = sizeof(*kf) + len;
    gpw_key_frag_t * kf = malloc(sz);
    if (kf == NULL)
        nomem_err(sz, "data");
    *next_gpw_key_ptr = kf;
    next_gpw_key_ptr  = &(kf->next);
    kf->size = len;
    memcpy(kf->data, buffer, len);
    (void)ctx;
}

static void *
gpw_finish(struct sha256_ctx *ctx, void *resbuf)
{
    static unsigned int const salt = 0x51BE1214;
    unsigned char * data;
    size_t len = 0;
    gpw_key_frag_t * kf = data_chain;
    while (kf != NULL) {
        len += kf->size;
        kf   = kf->next;
    }
    if (len < 32)
        die(GNU_PW_MGR_EXIT_BAD_SEED, too_short_fmt, len);
    data = malloc(len);
    if (data == NULL)
        nomem_err(sz, "data");
    kf   = data_chain;
    len  = 0;

    do  {
        gpw_key_frag_t * curr = kf;
        memcpy(data + len, kf->data, kf->size);
        len += kf->size;
        kf   = kf->next;
        free(kf);
    } while (kf != NULL);

    pbkdf2_hmac_sha256(len, data, 521, sizeof(salt), &salt,
                       256 / 8, resbuf);
    free(data);
    data_chain = NULL;
    next_gpw_key_ptr = &data_chain;
    (void)ctx;
}
#endif /* HAVE_LIBNETTLE */
