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

/**
 * Hash a password id into an option search string.
 * The options associated with a password id are associated
 * by means of an sha256 hash of it.
 *
 * @param[in] name  the password id string
 * @param[in] len   the id string length
 * @returns   a temporary allocation of the base64 encoding of the hash.
 */
static char *
make_pwid_mark(char const * name, size_t * len)
{
    char resbuf[256 / NBBY];
    char txtbuf[sizeof(long) + (sizeof(resbuf) * 3) / 2];
    struct sha256_ctx ctx;
    sha256_init_ctx(&ctx);
    sha256_process_bytes(name, strlen(name)+1, &ctx);
    sha256_finish_ctx(&ctx, resbuf);
    base64_encode(resbuf, sizeof(resbuf), txtbuf, sizeof(txtbuf));
    txtbuf[MARK_TEXT_LEN] = NUL;

    {
        char * mark = scribble_get(id_mark_fmt_LEN + MARK_TEXT_LEN);
        *len = sprintf(mark, id_mark_fmt, txtbuf);
        return mark;
    }
}

/**
 * set the options for a particular password id.
 * It modifies the \a optCookie field of \a DESC(CCLASS).
 *
 * @param[in]  name   the password id name
 */
static void
set_pwid_opts(char const * name)
{
    char const * cfg_text = load_config_file();
    char const * scan     = strstr(cfg_text, pw_id_tag);

    if (scan != NULL) {
        size_t mark_len;
        char * mark = make_pwid_mark(name, &mark_len);

        for (;;) {
            char * end;
            char * opt_text;
            size_t text_len;

            scan = next_pwid_opt(scan, mark, mark_len);
            if (scan == NULL)
                break;

            end  = strstr(scan, id_mark_end);
            if (end == NULL)
                break;

            text_len = end - scan;
            opt_text = scribble_get(text_len + 1);
            memcpy(opt_text, scan, text_len);
            opt_text[text_len] = NUL;
            optionLoadLine(&gnu_pw_mgrOptions, opt_text);
            scan = end + id_mark_end_LEN;
        }
    }

    sanity_check_cclass();
}

/**
 * Remove a replaced option.  A new instance of an option is about to
 * be inserted in the config file.  Remove any older instances of it.
 *
 * @param[in,out]   txt     the configuration text
 * @param[in]       mark    the password id hash in base64
 * @param[in]       m_len   the length of that hash
 * @param[in]       typ     the option type to remove
 */
static void
remove_opt(char const * txt, char const * mark, size_t m_len,
           set_opt_enum_t typ)
{
    char * buf = (char *)(void *)txt;
    for (;;) {
        char * p = strstr(buf, mark);
        if (p == NULL)
            return;

        if (find_set_opt_cmd(p + m_len) == typ) {
            buf = p;
            break;
        }
        buf = p + m_len;
    }
    {
        char * next = strstr(buf + m_len, pwtag_z);
        if (next == NULL) {
            while (buf[-1] == NL)  buf--;
            *(buf++) = NL;
            *buf = NUL;
        } else {
            size_t ln = strlen(next) + 1;
            memmove(buf, next, ln);
        }
    }
}

/**
 * Update password specific options.  The password-options must be
 * checked for being "defined" (set on the command line).  If they
 * are, remove them from the config data and append the new value.
 *
 * @param  name  password id
 */
static void
update_pwid_opts(char const * name)
{
    char const * cfg_text = load_config_file();
    char const * scan     = strstr(cfg_text, pw_id_tag);
    char * mark = NULL;
    bool   do_update      = false;

    if (scan == NULL) {
        size_t len = strlen(cfg_text);
        char * emk = scribble_get(len + pw_id_tag_LEN + 3);

        memcpy(emk, cfg_text, len);
        cfg_text = emk;
        emk += len;

        memcpy(emk, pw_id_tag, pw_id_tag_LEN);
        emk += pw_id_tag_LEN;

        *(emk++) = NL;
        *emk     = NUL;
    }

    {
        size_t mark_len;
        mark = make_pwid_mark(name, &mark_len);

        if (STATE_OPT(LOGIN_ID) == OPTST_DEFINED) {
            do_update = true;
            remove_opt(cfg_text, mark, mark_len, SET_CMD_LOGIN_ID);
        }

        if (STATE_OPT(CCLASS) == OPTST_DEFINED) {
            do_update = true;
            remove_opt(cfg_text, mark, mark_len, SET_CMD_CCLASS);
        }

        if (STATE_OPT(LENGTH) == OPTST_DEFINED) {
            do_update = true;
            remove_opt(cfg_text, mark, mark_len, SET_CMD_LENGTH);
        }

        if (STATE_OPT(SPECIALS) == OPTST_DEFINED) {
            do_update = true;
            remove_opt(cfg_text, mark, mark_len, SET_CMD_SPECIALS);
        }

        if (STATE_OPT(PBKDF2) == OPTST_DEFINED) {
            do_update = true;
            remove_opt(cfg_text, mark, mark_len, SET_CMD_NO_PBKDF2);
            remove_opt(cfg_text, mark, mark_len, SET_CMD_USE_PBKDF2);
        }
    }

    if (do_update) {
        char const * fnm = access_config_file();
        FILE * fp = fopen(fnm, "w");

        if (fp == NULL)
            fserr(GNU_PW_MGR_EXIT_NO_CONFIG, fopen_z, fnm);

        fputs(cfg_text, fp);
        if (STATE_OPT(LOGIN_ID) == OPTST_DEFINED)
            fprintf(fp, pwid_login_id_fmt, mark, OPT_ARG(LOGIN_ID));

        if (STATE_OPT(CCLASS) == OPTST_DEFINED) {
            tOptDesc *   od   = gnu_pw_mgrOptions.pOptDesc + INDEX_OPT_CCLASS;
            char const * save = od->optArg.argString;
            doOptCclass(OPTPROC_RETURN_VALNAME, od);
            fprintf(fp, pwid_cclass_fmt, mark, od->optArg.argString);
            free((void *)od->optArg.argString);
            od->optArg.argString = save;
        }

        if (STATE_OPT(LENGTH) == OPTST_DEFINED)
            fprintf(fp, pwid_length_fmt, mark, (unsigned int)OPT_VALUE_LENGTH);

        if (STATE_OPT(SPECIALS) == OPTST_DEFINED)
            fprintf(fp, pwid_specials_fmt, mark, OPT_ARG(SPECIALS));

        if (STATE_OPT(PBKDF2) == OPTST_DEFINED) {
            char const * how = ENABLED_OPT(PBKDF2) ? "use" : "no";
            fprintf(fp, pwid_pbkdf2_fmt, mark, how,
                    (unsigned int)OPT_VALUE_PBKDF2);
        }

        fclose(fp);
    }
}

/**
 * Find the next password id option in the config file that is not specified
 * on the command line.
 *
 * @param scan      current position in config file data
 * @param mark      the marker for "password id options"
 * @param mark_len  the length of that marker
 * @returns the character after the scan marker, or NULL
 */
static char const *
next_pwid_opt(char const * scan, char const * mark, size_t mark_len)
{
    for (;;) {
        scan = strstr(scan, mark);
        if (scan == NULL)
            return NULL;

        scan += mark_len;
        while (isspace((unsigned int)*scan))  scan++;

        /*
         * If the found option type is in DEFINED state, then it was set
         * on the command line and overrides whatever is in the config file.
         */
        switch (find_set_opt_cmd(scan)) {
        case SET_CMD_CCLASS:
            break; // always process this option

        case SET_CMD_LENGTH:
            if (STATE_OPT(LENGTH) == OPTST_DEFINED)
                continue;
            break;

        case SET_CMD_LOGIN_ID:
            if (STATE_OPT(LOGIN_ID) == OPTST_DEFINED)
                continue;
            break;

        case SET_CMD_NO_PBKDF2:
        case SET_CMD_USE_PBKDF2:
            if (STATE_OPT(PBKDF2) == OPTST_DEFINED)
                continue;
            break;

        case SET_CMD_SPECIALS:
            if (STATE_OPT(SPECIALS) == OPTST_DEFINED)
                continue;
            break;

        case SET_INVALID_CMD:
        default:
            goto no_next_pwid_opt;
        }
        return scan;
    }

    no_next_pwid_opt:
    {
        char * name = scribble_get(strlen(scan) + 1);
        char * end  = name;
        for (;;) {
            unsigned char ch = (unsigned char)*(scan++);
            if (! isalnum(ch))
                break;
            *(end++) = ch;
        }
        *end = NUL;
        die(GNU_PW_MGR_EXIT_NO_CONFIG, bad_cfg_ent, mark, name);
        /* NOTREACHED */
    }
    return NULL;
}

/**
 * fix up the options.  We insert two options:  --load-opts and
 * --no-load-opts.  The former specifies the config file we decided upon,
 * and the latter disables the processing of any other config files.
 * When the option processing is done, we'll choke and die if any other
 * config files got loaded.
 *
 * @param ac  pointer to argc argument to main
 * @param av  pointer to argv argument to main
 */
static void
fix_options(int * ac, char *** av)
{
    char *  fname = find_cfg_name();
    int     argc  = *ac + 3;
    char ** argv  = malloc (sizeof (void*) * (argc + 1));
    int     ix    = 0;

    /*
     * Insert some options of our own.
     */
    if (argv == NULL)
        nomem_err(sizeof (void*) * (argc + 1), "new arg vector");

    argv[ix++] = (*av)[0];
    argv[ix++] = (void *)load_opts;
    argv[ix++] = strdup(fname);
    argv[ix++] = (void *)no_load_opts;
    memcpy(argv + ix, (*av) + 1, sizeof(void*) * *ac);
    *ac = argc;
    *av = argv;

    /*
     * If there is no configured cclass option, then store the pre-option
     * processing value.
     */
    post_cfg_setting = OPT_VALUE_CCLASS;
}
