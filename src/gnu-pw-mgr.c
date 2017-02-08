/*
 *  This file is part of gpw.
 *
 *  Copyright (C) 2013-2017 Bruce Korb, all rights reserved.
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
    char * dta = (char *)data;
    unsigned int cclass = OPT_VALUE_CCLASS
        & (CCLASS_NO_ALPHA | CCLASS_NO_SPECIAL);

    // Check for PIN number password:
    //
    if (cclass == (CCLASS_NO_ALPHA | CCLASS_NO_SPECIAL)) {
        static uint32_t const bytes_per_val = 7
#if SIZEOF_CHARP > 4
            + 10
#endif
            ;
        uint32_t mx = (d_len / sizeof(uintptr_t)) * bytes_per_val;
        if (OPT_VALUE_LENGTH > mx)
            die(GNU_PW_MGR_EXIT_INVALID, pin_too_big,
                (uint32_t)OPT_VALUE_LENGTH, mx);

        fix_digit_pw(buf, (uintptr_t *)data);
        return;
    }

    base64_encode(dta, d_len, buf, bsz);

    // Check for confirmation answer password
    //
    if (HAVE_OPT(CONFIRM)) {
        buf[CONFIRM_LEN] = '\0';
        fix_lower_only_pw(buf);
        return;
    }

    buf[OPT_VALUE_LENGTH] = '\0';

    if (cclass == CCLASS_NO_ALPHA)
        fix_no_alpha_pw(buf);
    else
        fix_std_pw(buf);
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
    if (HAVE_OPT(CONFIRM))
        sha256_process_bytes(OPT_ARG(CONFIRM), strlen(OPT_ARG(CONFIRM))+1, &ctx);
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
    size_t cfm_len = HAVE_OPT(CONFIRM) ? (strlen(OPT_ARG(CONFIRM)) + 1) : 0;

    size_t hash_ln = 4 + ((bsz * 6) >> 3);

    char * nam_tag = scribble_get(tag_len + nam_len + cfm_len);
    char * hash_bf = scribble_get(hash_ln);
    Gc_rc rc;

    memcpy(nam_tag, tag, tag_len);
    memcpy(nam_tag + tag_len, nam, nam_len);
    tag_len += nam_len;
    if (cfm_len > 0) {
        memcpy(nam_tag + tag_len, OPT_ARG(CONFIRM), cfm_len);
        tag_len += cfm_len;
    }

    rc = gc_pbkdf2_sha1(
        nam_tag, tag_len,
        txt, strlen(txt) + 1,
        OPT_VALUE_PBKDF2,
        hash_bf, hash_ln);
    if (rc != GC_OK)
        die(GNU_PW_MGR_EXIT_INVALID, pbkdf2_err_fmt, rc);

    adjust_pw(buf, bsz, (unsigned char *)hash_bf, hash_ln);
}

static void
print_pwid_header(char const * name)
{
    static char const hdr_fmt[]  = "password id '%s'%s:\n";
    static char const is_sec[]   = " (shared password)";
    printf(hdr_fmt, name, ENABLED_OPT(SHARED) ? is_sec : "");
}

/**
 * Print the passwords for \a name.
 * @param name  the name/id for which a password is needed
 */
static void
print_pwid_status(char const * name)
{
    static char const lstr_fmt[] = "  %-10s %s\n";
    static char const ldig_fmt[] = "  %-10s %u\n";

    bool have_data = false;

    if (HAVE_OPT(LOGIN_ID)) {
        have_data = true;
        print_pwid_header(name);
        printf(lstr_fmt, "login-id", OPT_ARG(LOGIN_ID));
    }

    if (HAVE_OPT(LENGTH)) {
        if (! have_data) {
            print_pwid_header(name);
            have_data = true;
        }
        printf(ldig_fmt, "length", (unsigned int)OPT_VALUE_LENGTH);
    }

    if (HAVE_OPT(PBKDF2) || (OPT_VALUE_LENGTH > (MIN_BUF_LEN - 8))) {
        if (! have_data) {
            print_pwid_header(name);
            have_data = true;
        }
        if (ENABLED_OPT(PBKDF2) || (OPT_VALUE_LENGTH > (MIN_BUF_LEN - 8)))
            printf(ldig_fmt, "pbkdf2 ct", (unsigned int)OPT_VALUE_PBKDF2);
        else
            printf(lstr_fmt, "pbkdf2", "not used");
    }

    if (HAVE_OPT(SPECIALS)) {
        if (! have_data) {
            print_pwid_header(name);
            have_data = true;
        }
        printf(lstr_fmt, "spec chars", OPT_ARG(SPECIALS));
    }

    if (HAVE_OPT(CCLASS)) {
        char const * names;

        if (! have_data) {
            print_pwid_header(name);
            have_data = true;
        }
        doOptCclass(OPTPROC_RETURN_VALNAME, &DESC(CCLASS));
        names = DESC(CCLASS).optArg.argString;
        printf(lstr_fmt, "ch-class", names);
        free((void *)names);
    }

    if (! have_data)
        printf("The %s password id has all default settings\n", name);
}

/**
 * select the characters for a selected character password.
 * @param[in,out] txtbuf the full password overwritten by
 *   the abbreviated password.
 */
static void
select_chars(unsigned char * txtbuf)
{
    int const  len = strlen((char *)txtbuf);
    char *      pn = NULL;
    char const * p = OPT_ARG(SELECT_CHARS);

    char buf[64], *pd = buf;

    /*
     * the result length cannot be larger than the input length.
     */
    int const lim = (len > sizeof(buf)) ? sizeof(buf) : len;

    errno = 0;
    for (;;) {
        long v = strtol(p, &pn, 0);
        if ((errno != 0) || (v < 1) || (v > len))
            die(GNU_PW_MGR_EXIT_BAD_SELECT_CHARS, OPT_ARG(SELECT_CHARS));
        *(pd++) = txtbuf[v-1];
        if (pd >= buf + lim)
            die(GNU_PW_MGR_EXIT_BAD_SELECT_CHARS, OPT_ARG(SELECT_CHARS));
        p = pn + strspn(pn, " ,");
        if (*p == NUL)
            break;
    }

    *pd = NUL;
    strcpy((char *)txtbuf, buf);
}

static bool
print_one_pwid(tOptionValue const * seed_opt, char const * name)
{
    if (seed_opt->valType != OPARG_TYPE_HIERARCHY)
        die(GNU_PW_MGR_EXIT_BAD_SEED, bad_seed);

    /*
     * Ensure that we have a reasonably current seed.
     * If not, we ignore the seed.
     */
    {
        tOptionValue const * ver = optionGetValue(seed_opt, s_ver_z);

        if ((ver == NULL) || (ver->valType != OPARG_TYPE_NUMERIC)) {
            tOptionValue const * tag = optionGetValue(seed_opt, tag_z);
            warning_msg(too_old_z, tag->v.strVal);
            return false;
        }
    }

    /*
     *  make sure that the password id setting for "shared"
     *  matches that of our seed.
     */
    {
        tOptionValue const * sec = optionGetValue(seed_opt, sec_pw_id);

        if ((sec == NULL) != (! HAVE_OPT(SHARED)))
            return false;
    }

    /*
     * The gauntlett has been run.  Now print the password.
     */
    tOptionValue const * tag = optionGetValue(seed_opt, tag_z);
    tOptionValue const * txt = optionGetValue(seed_opt, text_z);

    if (  (tag->valType != OPARG_TYPE_STRING)
       || (tag->valType != OPARG_TYPE_STRING))
        die(GNU_PW_MGR_EXIT_BAD_SEED, bad_seed);

    /*
     * Use the PBKDF function if it is requested or if the result
     * length exceeds what we can provide with 256 bits of hash
     * (40 bytes).
     */
    /*
     * The "txtbuf" is much larger than needed.  It gets trimmed.
     * This way, base64encode can encode all the data,
     */
    size_t buf_len = (OPT_VALUE_LENGTH > (MIN_BUF_LEN - 8))
        ? OPT_VALUE_LENGTH + 16 : MIN_BUF_LEN;
    unsigned char * txtbuf = scribble_get(buf_len);

    if (ENABLED_OPT(PBKDF2) || (OPT_VALUE_LENGTH > (MIN_BUF_LEN - 8)))
        get_pbkdf2_pw((char *)txtbuf, buf_len,
                      tag->v.strVal, txt->v.strVal, name);
    else
        get_dft_pw((char *)txtbuf, buf_len,
                   tag->v.strVal, txt->v.strVal, name);

    if (HAVE_OPT(SELECT_CHARS))
        select_chars(txtbuf);

    printf(pw_fmt, tag->v.strVal, txtbuf);
    return true;
}

/**
 * Print the passwords for \a name.
 * @param name  the name/id for which a password is needed
 */
static void
print_pwid(char const * name)
{
    char const *    pfx    = "";
    tOptionValue const * ov = optionFindValue(&DESC(SEED), NULL, NULL);
    bool printed_pw = false;

    if (*name == '\0')
        die(GNU_PW_MGR_EXIT_NO_PWID, no_pwid);

    set_pwid_opts(name);
    if (HAVE_OPT(STATUS)) {
        print_pwid_status(name);
        return;
    }

    if (HAVE_OPT(DELETE)) {
        remove_pwid(name);
        return;
    }

    scribble_free();

    if (! HAVE_OPT(LOGIN_ID)) {
        if (! HAVE_OPT(NO_HEADER))
            fputs(hdr_str, stdout);

    } else {
        size_t l = strlen(OPT_ARG(LOGIN_ID));
        char * t = scribble_get(l + 2);
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
        printed_pw |= print_one_pwid(ov, name);
        ov = optionFindNextValue(&DESC(SEED), ov, NULL, NULL);
    } while (ov != NULL);

    if (! printed_pw)
        die(GNU_PW_MGR_EXIT_NO_SEED, no_passwords,
            ENABLED_OPT(SHARED) ? sec_pw_type : "");

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

static void
proc_dom_opts(void)
{
    int  ct = STACKCT_OPT(DOMAIN);
    char const ** dom_list = STACKLST_OPT(DOMAIN) + ct - 1;
    bool list_doms = false;

    do {
        char const * dom = *(dom_list++);
        if ((*dom == '-') && (dom[1] == NUL)) {
            list_doms = true;
            continue;
        }
    } while (--ct > 0);
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

    if (HAVE_OPT(DOMAIN))
        proc_dom_opts();

    /*
     * There are four operational modes:
     *
     * 1) command line operands signify printing a password, otherwise
     * 2) not having a --tag option says to read a password id from stdin, else
     * 3) not having --text option says to remove a seed, else
     * 4) add a new password seed using --tag and --text
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
         * If the domain option was provided and we don't have a tag opt,
         * then presume someone just wanted to fiddle domain info.
         */
        if (! HAVE_OPT(DOMAIN))
            stdin_pwid();

    } else if (HAVE_OPT(TEXT)) {
        if (HAVE_OPT(SHARED) && ! ENABLED_OPT(SHARED))
            usage_message(disable_second);
        add_seed();

    } else {
        if (HAVE_OPT(SHARED))
            usage_message(shared_removal);
        rm_seed();
    }

    secure_cfg_file();

    scribble_deinit();
    return GNU_PW_MGR_EXIT_SUCCESS;
}
