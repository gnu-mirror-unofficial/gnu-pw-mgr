/*
 *  This file is part of gpw.
 *
 *  Copyright (C) 2013 Bruce Korb, all rights reserved.
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
#include "opts.h"
#include "fwd.h"

/**
 * Convert the hash data to a password.  Uses base64 encoding, mostly,
 * but atoi for PIN numbers (decimal digits only passwords).
 *
 * @param buf   result buffer
 * @param bsz   buffer size
 * @param data  the raw hash code
 * @param d_len the length of the raw hash
 */
static void
adjust_pw(char * buf, size_t bsz, unsigned char * data, size_t d_len)
{
    switch (OPT_VALUE_CCLASS & (CCLASS_NO_ALPHA | CCLASS_NO_SPECIAL)) {
    case 0:
    case CCLASS_NO_SPECIAL:
        base64_encode(data, d_len, buf, bsz);
        buf[OPT_VALUE_LENGTH] = '\0';
        fix_std_pw(buf);
        break;

    case CCLASS_NO_ALPHA:
        base64_encode(data, d_len, buf, bsz);
        buf[OPT_VALUE_LENGTH] = '\0';
        fix_no_alpha_pw(buf);
        break;

    case CCLASS_NO_ALPHA | CCLASS_NO_SPECIAL:
    {
#if SIZEOF_CHARP > 4
        uint32_t const bytes_per_val = 17;
#else
        uint32_t const bytes_per_val = 7;
#endif
        uint32_t mx = (sizeof(uintptr_t) / d_len) * bytes_per_val;
        if (OPT_VALUE_LENGTH > mx)
            die(GNU_PW_MGR_EXIT_INVALID, pin_too_big,
                (uint32_t)OPT_VALUE_LENGTH, mx);

        fix_digit_pw(buf, (uintptr_t *)data);
    }
    }
}

/**
 * hash and encode the seed tag, the seed and the password id.
 * Use the original glue-the-text-together-and-hash method.
 *
 * @param buf   result buffer
 * @param bsz   buffer size
 * @param tag   the seed tag
 * @param txt   the password seed
 * @param nam   the password id
 */
static void
get_dft_pw(char * buf, size_t bsz,
           char const * tag, char const * txt, char const * nam)
{
    union {
        uintptr_t       data[256 / (NBBY * sizeof(uintptr_t))];
        unsigned char   sha_buf[256 / NBBY];
    } sum;

    struct sha256_ctx ctx;
    sha256_init_ctx(&ctx);
    sha256_process_bytes(tag, strlen(tag)+1, &ctx);
    sha256_process_bytes(txt, strlen(txt)+1, &ctx);
    sha256_process_bytes(nam, strlen(nam)+1, &ctx);
    sha256_finish_ctx(&ctx, sum.sha_buf);

    adjust_pw(buf, bsz, sum.sha_buf, sizeof(sum.sha_buf));
}

/**
 * hash and encode the seed tag, the seed and the password id.
 * Use the pbkdf2 method. (Password Based Key Derivation Function, version 2)
 *
 * @param buf   result buffer
 * @param bsz   buffer size
 * @param tag   the seed tag
 * @param txt   the password seed
 * @param nam   the password id
 */
static void
get_pbkdf2_pw(char * buf, size_t bsz,
              char const * tag, char const * txt, char const * nam)
{
    size_t tag_len = strlen(tag) + 1;
    size_t nam_len = strlen(nam) + 1;
    size_t hash_ln = 4 + ((bsz * 6) >> 3);

    char * nam_tag = scribble_get(tag_len + nam_len);
    char * hash_bf = scribble_get(hash_ln);
    Gc_rc rc;

    memcpy(nam_tag, tag, tag_len);
    memcpy(nam_tag + tag_len, nam, nam_len);

    rc = gc_pbkdf2_sha1(
        nam_tag, tag_len + nam_len,
        txt, strlen(txt) + 1,
        OPT_VALUE_PBKDF2,
        hash_bf, hash_ln);
    if (rc != GC_OK)
        die(GNU_PW_MGR_EXIT_INVALID, pbkdf2_err_fmt, rc);

    adjust_pw(buf, bsz, hash_bf, hash_ln);
}

/**
 * Print the passwords for \a name.
 * @param name  the name/id for which a password is needed
 */
static void
print_pwid(char const * name)
{
#   define MIN_LEN ((256 / NBBY) + (256 / (NBBY * 2))) // 48
    size_t buf_len = MIN_LEN;
    unsigned char * txtbuf;

    int ix = 0;
    char const * pfx = "";
    tOptionValue const * ov = optionFindValue(&DESC(SEED), NULL, NULL);

    set_pwid_opts(name);
    scribble_free();

    if (OPT_VALUE_LENGTH > (MIN_LEN - 8)) // > 40
        buf_len = OPT_VALUE_LENGTH + 16;

    /*
     * The "txtbuf" is much larger than needed.  It gets trimmed.
     * This way, base64encode can encode all the data,
     */
    txtbuf = scribble_get(buf_len);

    if (! HAVE_OPT(LOGIN_ID)) {
        if (! HAVE_OPT(NO_HEADER))
            fputs(hdr_str, stdout);

    } else {
        size_t l = strlen(OPT_ARG(LOGIN_ID));
        char * t;
        t = scribble_get(l + 2);
        memcpy(t, OPT_ARG(LOGIN_ID), l);
        t[l++] = ' ';
        t[l]   = NUL;
        pfx    = t;
        if (! HAVE_OPT(NO_HEADER))
            printf(hdr_hint, pfx);
    }

    /*
     * For each <seed> value in the config file, print a password.
     */
    do  {
        tOptionValue const * tag, * txt;

        if (ov->valType != OPARG_TYPE_HIERARCHY)
            die(GNU_PW_MGR_EXIT_BAD_SEED, bad_seed);

        tag = optionGetValue(ov, tag_z);
        txt = optionGetValue(ov, text_z);
        if (  (tag->valType != OPARG_TYPE_STRING)
           || (tag->valType != OPARG_TYPE_STRING))
            die(GNU_PW_MGR_EXIT_BAD_SEED, bad_seed);

        /*
         * Use the PBKDF function if it is requested or if the result
         * length exceeds what we can provide with 256 bits of hash
         * (40 bytes).
         */
        if (ENABLED_OPT(PBKDF2) || (OPT_VALUE_LENGTH > (MIN_LEN - 8)))
            get_pbkdf2_pw(txtbuf, buf_len, tag->v.strVal, txt->v.strVal, name);
        else
            get_dft_pw(txtbuf, buf_len, tag->v.strVal, txt->v.strVal, name);

        printf(pw_fmt, tag->v.strVal, txtbuf);

    } while (ov = optionFindNextValue(&DESC(SEED), ov, NULL, NULL),
             ov != NULL);

    update_pwid_opts(name);
}

/**
 * assemble operands into one space separated argument.
 * It succeeds or dies.
 *
 * @param[in] argc  operand count
 * @param[in] argv  operand list
 * @returns   the assembled string.
 */
static char const *
assemble_arg(int argc, char ** argv)
{
    char * res, * scan;

    size_t len = argc;
    int    ct  = argc;
    while (--ct >= 0)
        len += strlen(argv[ct]);
    scan = res = malloc(len);
    if (res == NULL)
        nomem_err(len, "password id");

    ct = argc;
    for (;;) {
        len = strlen(*argv);
        memcpy(scan, *(argv++), len);
        scan += len;
        if (--ct <= 0)
            break;
        *(scan++) = ' ';
    }
    *scan = NUL;
    return res;
}

/**
 * Remove leading and trailing white space.
 * This may yield an empty string.
 *
 * @param[in,out] in   the input string
 * @returns the address of the first non-whitespace character
 */
static char *
trim(char * in)
{
    char * res;

    while (isspace((unsigned int)*in))  in++;

    res = in;
    in += strlen(in);
    while ((in > res) && isspace((unsigned int)(in[-1]))) in--;
    *in = NUL;

    return res;
}

/**
 * Read a password identifier from standard input.  Provided both stdin and
 * stdout are TTY devices.
 */
static void
stdin_pwid(void)
{
# ifdef HAVE_TCGETATTR
    struct termios orig_term;
    bool restore_stdin = false;
    static char const stdio_funs[] =
        "tcgetattr/tcsetattr/fputs/fflush/fread";
# else
    static char const stdio_funs[] =
        "fputs/fflush/fread";
# endif
    char pwid[4096];

    if (! isatty(STDIN_FILENO) || ! isatty(STDOUT_FILENO))
        usage_message( no_pwid_fmt);

    do  {
        if (isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
# ifdef HAVE_TCGETATTR
            struct termios noecho_term;

            if (tcgetattr(STDIN_FILENO, &orig_term) != 0)           break;

            noecho_term = orig_term;
            noecho_term.c_lflag &= ~ECHO;
            if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &noecho_term) != 0)
                break;

            restore_stdin = true;
# endif
            if (fputs( pw_prompt, stdout) < 0)                      break;
            if (fflush(stdout) != 0)                                break;
        }
        if (fgets(pwid, sizeof(pwid), stdin) != pwid)               break;

        print_pwid( trim( pwid));

# ifdef HAVE_TCGETATTR
        if (restore_stdin)
            (void) tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_term);
# endif
        return;
    } while (0);

# ifdef HAVE_TCGETATTR
    if (restore_stdin)
        (void) tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_term);
# endif
    fserr(GNU_PW_MGR_EXIT_INVALID, stdio_funs, stdin_out_z);
    /* NOTREACHED */
}

/**
 * Main procedure.
 * @param argc   argument count
 * @param argv   argument vector
 */
int
main(int argc, char ** argv)
{
    scribble_init();
    fix_options(&argc, &argv);
    {
        int ct = optionProcess(&gnu_pw_mgrOptions, argc, argv);
        argc -= ct;
        argv += ct;
    }
    if (gnu_pw_mgrOptions.pOptDesc[INDEX_OPT_LOAD_OPTS].optOccCt != 1)
        die(GNU_PW_MGR_EXIT_INVALID, had_load_opts);

    /*
     * There are three operational modes: add a new seed, remove an old seed
     * and print a password.  If we have any operands, we must be printing a
     * password.  We must have found a seed option in the config file and
     * we cannot have a --text or --tag option specified.
     */
    if (argc > 0) {
        char const * arg;

        if (! HAVE_OPT(SEED))
            die(GNU_PW_MGR_EXIT_NO_SEED, no_seeds);

        if (HAVE_OPT(TEXT) || HAVE_OPT(TAG))
            usage_message(tag_pwid_conflict);

        if (argc == 1)
            arg = *argv;
        else
            arg = assemble_arg(argc, argv);
        
        print_pwid(arg);

    } else if (! HAVE_OPT(TAG)) {
        /*
         * libopts has ensured that we do not have --text, so we must
         * be reading in a password id from standard input
         */
        stdin_pwid();

    } else if (HAVE_OPT(TEXT))
        add_seed();

    else
        rm_seed();

    secure_cfg_file();

    scribble_deinit();
    return GNU_PW_MGR_EXIT_SUCCESS;
}
