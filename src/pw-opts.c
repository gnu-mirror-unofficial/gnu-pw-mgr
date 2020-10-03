/**
 *  @file pw-opts.c
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
    char resbuf[256 / NBBY]; // 256 bits (Number of Bits per BYte)
    char txtbuf[sizeof(long) + (sizeof(resbuf) * 3) / 2];
    struct sha256_ctx ctx;
    sha256_init_ctx(&ctx);
    sha256_process_bytes(name, strlen(name)+1, &ctx);
    sha256_finish_ctx(&ctx, resbuf);
    base64_encode(resbuf, sizeof(resbuf), txtbuf, sizeof(txtbuf));
    txtbuf[MARK_TEXT_LEN] = NUL;

    {
        static unsigned long const mark_size =
            id_mark_fmt_LEN + MARK_TEXT_LEN + 10;
        char * mark = scribble_get(mark_size);
        size_t altlen;
        if (len == NULL)
            len = &altlen;
        *len = sprintf(mark, id_mark_fmt, txtbuf);
        return mark;
    }
}

static char const *
day_to_string(char const * day_str)
{
    static char time_buf[time_fmt_LEN + 4];

    time_t day = strtoul(day_str, NULL, 10) * SECONDS_IN_DAY;
    struct tm *tmday = localtime(&day);
    if (tmday == NULL)
        fserr(GNU_PW_MGR_EXIT_NO_MEM, "localtime", "");
    strftime(time_buf, sizeof(time_buf), time_fmt, tmday);
    return time_buf;
}

/**
 * Find the next password id option in the config file that is not specified
 * on the command line. It is a command line option if STATE_OPT(xx) is
 * OPTST_DEFINED.
 *
 * @param scan      current position in config file data
 * @param mark      the marker for "password id options"
 * @param mark_len  the length of that marker
 *
 * @returns the character after the scan marker, or NULL
 */
static char const *
next_pwid_opt(char const * scan, char const * mark, size_t mark_len)
{
    char * opt_text;

    for (;;) {
        scan = strstr(scan, mark);
        if (scan == NULL)
            return NULL;

        scan += mark_len;
        while (isspace((unsigned int)*scan))
            scan++;
        opt_text = strchr(scan, '>');
        if (opt_text == NULL)
            return NULL;
        while (isspace((unsigned int)*++opt_text))  ;

        /*
         * If the found option type is in DEFINED state, then it was set
         * on the command line and overrides whatever is in the config file.
         */
        switch (find_set_opt_cmd(opt_text)) {
        case SET_CMD_LOGIN_ID:
            if (STATE_OPT(LOGIN_ID) == OPTST_DEFINED)
                continue;
            break;

        case SET_CMD_LENGTH:
            if (STATE_OPT(LENGTH) == OPTST_DEFINED)
                continue;
            break;

        case SET_CMD_CCLASS:
            break; // always process this option

        case SET_CMD_NO_PBKDF2:
        case SET_CMD_USE_PBKDF2:
            if (HAVE_OPT(REHASH))
                continue;

            if (strncmp(scan, date_z, date_z_LEN) == 0)
                rehash_date = day_to_string(scan + date_z_LEN);
            else
                rehash_date = pw_undated;
            break;

        case SET_CMD_SPECIALS:
            if (STATE_OPT(SPECIALS) == OPTST_DEFINED)
                continue;
            break;

        case SET_CMD_SHARED:
            if (STATE_OPT(SHARED) == OPTST_DEFINED)
                continue;
            break;

        case SET_INVALID_CMD:
        default:
            goto no_next_pwid_opt;
        }
        return opt_text;
    }

    no_next_pwid_opt:
    {
        char * name = scribble_get(strlen(opt_text) + 1);
        char * end  = name;
        for (;;) {
            unsigned char ch = (unsigned char)*(opt_text++);
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
 * set the config file stored options for a particular password id.
 * It modifies the \a optCookie field of \a DESC(CCLASS).
 *
 * @param[in]  opt_text  the text of the configured value
 *
 * @returns a pointer to the text immediately after the option
 */
static char *
load_one_stored_opt(char const * opt_text)
{
    char * opt_buf;
    size_t text_len;
    char * end = strstr(opt_text, id_mark_end);
    if (end == NULL)
        die(GNU_PW_MGR_EXIT_BAD_CONFIG, no_id_mark_end, opt_text);

    text_len = end - opt_text;
    opt_buf = scribble_get(text_len + 1);
    memcpy(opt_buf, opt_text, text_len);
    opt_buf[text_len] = NUL;
    optionLoadLine(&gnu_pw_mgrOptions, opt_buf);
    return end + id_mark_end_LEN;
}

/**
 * set the config file stored options for a particular password id.
 * It modifies the \a optCookie field of \a DESC(CCLASS).
 *
 * @param[in]  mark     the marker for this password id
 * @param[in]  mark_len the length of the marker
 *
 * @returns true if the PBKDF2 option was set via the rehash option
 */
static bool
set_stored_opts(char * mark, size_t mark_len)
{
    bool res = false;

    /*
     * Find the marker that separates the seeds from the
     * password id options
     */
    char const * scan = config_file_text;

    if (HAVE_OPT(REHASH)) {
        rehash_date = pw_today;
        DESC(PBKDF2).fOptState &= OPTST_PERSISTENT_MASK;
        DESC(PBKDF2).fOptState |= OPTST_DEFINED;
        OPT_VALUE_PBKDF2        = OPT_VALUE_REHASH;
        res = true;
    }

    while (scan = next_pwid_opt(scan, mark, mark_len),
           scan != NULL) {
        have_stored_opts = true;
        scan = load_one_stored_opt(scan);
    }

    return res;
}

/**
 * Sometimes the cclass option depends on the old value. Fix it up, in case.
 *
 * @param[in]  buf     scan this buffer for the desired option
 * @param[in]  mark    the password id hash in base64
 * @param[in]  m_len   the length of that hash
 * @param[in]  typ     the enumerated value of the searched for entry
 *
 * @returns a pointer to the start of the entry, or NULL
 */
static char *
search_for_option(char * buf, char const * mark, size_t m_len, set_opt_enum_t typ)
{
    for (;;) {
        char * popt = strstr(buf, mark);
        char * p    = popt;

        if (p == NULL)
            return NULL;

        /*
         * The marker may have more than just <pwtag id="..">, so
         * scan over whatever else and past the closing '>'.
         */
        p = strchr(p, '>');
        if (p == NULL)
	    die(GNU_PW_MGR_EXIT_BAD_CONFIG, no_id_mark_end, mark);

        /*
         * Convert the next part into the option type enumeration
         * and see if it matches the one we're looking for.
         * Spellings are "allowed" to vary, so it's not just a
         * strncmp().
         */
        if (find_set_opt_cmd(++p) == typ)
	    return popt;

        buf = p + id_mark_end_LEN;
    }
}

/**
 * Before removing a cclass option from the configuration text,
 * make sure the newly defined option doesn't start with a '+' or '-'.
 * If it does, then we are modifying a previously existing value.
 *
 * @param[in]  mark    the password id hash in base64
 * @param[in]  m_len   the length of that hash
 * @param[in]  typ     the enumerated value of the searched for entry
 */
static void
adjust_cclass_val(char const * mark, size_t m_len)
{
    intptr_t     new_cc = (intptr_t)OPT_VALUE_CCLASS;
    intptr_t     old_cc;
    char *       buf =
        search_for_option(config_file_text, mark, m_len, SET_CMD_CCLASS);

    if (buf == NULL) {
        old_cc = (intptr_t)(
            HAVE_OPT(DEFAULT_CCLASS)
            ? DESC(DEFAULT_CCLASS).optCookie
            : CclassCookieBits );
    } else {
        char * scan = strchr(buf, '>');
        if (scan == NULL)
            die(GNU_PW_MGR_EXIT_BAD_CONFIG, no_id_mark_end, buf);

        (void) load_one_stored_opt(scan+1);

        old_cc = OPT_VALUE_CCLASS;
    }

    {
        intptr_t new = (tweak_prev_cclass < 0)
            ? (old_cc & ~new_cc) : (old_cc | new_cc);

        DESC(CCLASS).fOptState &= OPTST_PERSISTENT_MASK;
        DESC(CCLASS).fOptState |= OPTST_DEFINED;
        DESC(CCLASS).optCookie  = (void*)new;
    }
}

/**
 * Before removing a cclass option from the configuration text,
 * make sure the newly defined option doesn't start with a '+' or '-'.
 * If it does, then we are modifying a previously existing value.
 *
 * @param[in]  mark    the password id hash in base64
 * @param[in]  m_len   the length of that hash
 */
static void
adjust_pbkdf2_val(char const * mark, size_t m_len)
{
    uint64_t     old_pbkdf2 = (intptr_t)PBKDF2_DFT_ARG;
    uint64_t     new_pbkdf2 = OPT_VALUE_REHASH;
    char *       buf =
        search_for_option(config_file_text, mark, m_len, SET_CMD_USE_PBKDF2);

    /*
     * If there is an entry, then pull it out and stash the "old" value.
     */
    if (buf != NULL) {
        char * scan = strchr(buf, '>');
        if (scan == NULL)
            die(GNU_PW_MGR_EXIT_BAD_CONFIG, no_id_mark_end, buf);

        (void) load_one_stored_opt(scan+1);

        old_pbkdf2 = OPT_VALUE_PBKDF2;
    }

    /*
     * Now adjust the value and see if it has changed.
     */
    {
        uint64_t new = (tweak_prev_rehash < 0)
            ? (old_pbkdf2 - new_pbkdf2) : (old_pbkdf2 + new_pbkdf2);

        if (new == 0) {
            new = (uint64_t)(intptr_t)PBKDF2_DFT_ARG;
            warning_msg(rehash_set_fmt, new);

        } else if (new > (uint64_t)100000) {
            new = 1;
            warning_msg(rehash_set_fmt, new);
        }

        DESC(PBKDF2).fOptState &= OPTST_PERSISTENT_MASK;
        DESC(PBKDF2).fOptState |= OPTST_DEFINED;
        OPT_VALUE_PBKDF2        = new;
    }
}

/**
 * Sometimes the cclass option depends on the old value. Fix it up, in case.
 *
 * @param[in]  mark    the password id hash in base64
 * @param[in]  m_len   the length of that hash
 *
 * @returns true if the option was actually removed
 */
static bool
remove_opt(char const * mark, size_t m_len, set_opt_enum_t typ)
{
    char * buf = config_file_text;

    while (buf = search_for_option(buf, mark, m_len, typ),
	   buf != NULL) {

	char * next = strstr(buf + m_len, id_mark_end);
	if (next == NULL)
	    die(GNU_PW_MGR_EXIT_BAD_CONFIG, no_id_mark_end, buf);

	next += id_mark_end_LEN;
	while (*next == NL) next++;

	if (*next == NUL) {
	    *buf = NUL;
	    break;
	}

	memmove(buf, next, strlen(next) + 1);
    }

    return true;
}

/**
 * check for updated options
 *
 * @param mark     the string that marks all options for the current password id
 * @param mark_len the length of that string
 *
 * @returns true if any stored options need updating.
 */
static bool
remove_defined_opts(char * mark, size_t mark_len)
{
    bool res = false;

    if (STATE_OPT(LOGIN_ID) == OPTST_DEFINED)
        res |= remove_opt(mark, mark_len, SET_CMD_LOGIN_ID);

    if (STATE_OPT(LENGTH) == OPTST_DEFINED)
        res |= remove_opt(mark, mark_len, SET_CMD_LENGTH);

    if (STATE_OPT(CCLASS) == OPTST_DEFINED) {
        if (tweak_prev_cclass != 0) {
            adjust_cclass_val(mark, mark_len);
            res = true;
        }
        res |= remove_opt(mark, mark_len, SET_CMD_CCLASS);
    }

    if (HAVE_OPT(REHASH)) {
        if (tweak_prev_rehash != 0) {
            adjust_pbkdf2_val(mark, mark_len);
            res = true;
        }
        res |= remove_opt(mark, mark_len, SET_CMD_NO_PBKDF2);
        res |= remove_opt(mark, mark_len, SET_CMD_USE_PBKDF2);
    }

    if (STATE_OPT(SPECIALS) == OPTST_DEFINED)
        res |= remove_opt(mark, mark_len, SET_CMD_SPECIALS);

    if (STATE_OPT(SHARED) == OPTST_DEFINED)
        res |= remove_opt(mark, mark_len, SET_CMD_SHARED);

    return res;
}

/**
 * set the options for a particular password id.
 * It modifies the \a optCookie field of \a DESC(CCLASS).
 *
 * @param[in]  pw_id   the password id
 */
static void
set_pwid_opts(char const * pw_id)
{
    size_t mark_len;
    char const * scan = config_file_text;
    char *       mark = make_pwid_mark(pw_id, &mark_len);

    /*
     * Get rid of any stored options that appear on the command line
     */
    update_stored_opts |= remove_defined_opts(mark, mark_len);

    /*
     * now set all the options specified in the config file.
     * None will conflict with command line options since we just
     * removed all the conflicts with the ones stored.
     */
    update_stored_opts |= set_stored_opts(mark, mark_len);

    /*
     * If we have a default character class and we did not find
     * any stored options for this password id, then set the
     * caracter classes to the default and note that we must
     * rewrite the cclass option. (Setting state to "DEFINED"
     * tells the wrap up code that the value must be saved.)
     */
    if ((! HAVE_OPT(CCLASS)) && HAVE_OPT(DEFAULT_CCLASS)) {
        SET_OPT_CCLASS((uintptr_t) (void*) OPT_ARG(DEFAULT_CCLASS));
        DESC(CCLASS).fOptState &= OPTST_PERSISTENT_MASK;
        DESC(CCLASS).fOptState |= OPTST_DEFINED;
        update_stored_opts      = true;
    }
    if (HAVE_OPT(CCLASS))
        sanity_check_cclass();
}

/**
 * Update password specific options.  The password-options must be
 * checked for being "defined" (set on the command line).
 *
 * @param  name  password id
 */
static void
update_pwid_opts(char const * name)
{
    if (strstr(config_file_text, pw_id_tag) == NULL) {
        size_t len = strlen(config_file_text);
        char * emk = scribble_get(len + pw_id_tag_LEN + 3);

        memcpy(emk, config_file_text, len);
        config_file_text = emk;
        emk += len;

        memcpy(emk, pw_id_tag, pw_id_tag_LEN);
        emk += pw_id_tag_LEN;

        *(emk++) = NL;
        *emk     = NUL;
    }

    /*
     * We had at least one command line option.
     */
    {
        char * mark = make_pwid_mark(name, NULL);
        char const * fnm = access_config_file();
        FILE * fp = fopen(fnm, "w");

        if (fp == NULL)
            fserr(GNU_PW_MGR_EXIT_NO_CONFIG, fopen_z, fnm);

        fputs(config_file_text, fp);
        if (STATE_OPT(LOGIN_ID) == OPTST_DEFINED)
            fprintf(fp, pwid_login_id_fmt, mark, OPT_ARG(LOGIN_ID));

        if (STATE_OPT(LENGTH) == OPTST_DEFINED)
            fprintf(fp, pwid_length_fmt, mark, (unsigned int)OPT_VALUE_LENGTH);

        if (STATE_OPT(CCLASS) == OPTST_DEFINED) {
            /*
             * The CCLASS is specified as a series of bits. Call the option
             * handling function with a magic address for the option structure
             * and it will replace the binary value with an allocated string.
             */
            tOptDesc *   od   = &DESC(CCLASS);
            char const * save = od->optArg.argString;
            doOptCclass(OPTPROC_RETURN_VALNAME, od);
            fprintf(fp, pwid_cclass_fmt, mark, od->optArg.argString);
            free((void *)od->optArg.argString);
            od->optArg.argString = save;
        }

        /*
         * We are here because a new persistent option was specified.
         *
         * If either --rehash was specified *OR*
         *    some other persistent option was specified,
         * then we'll stash the rehash value and timestamp the password id
         *
         * NOTE CAREFULLY: if there is a previous rehash value, then
         * "have_stored_opts" will be true and we won't update the date.
         */
        if (HAVE_OPT(REHASH) || (! have_stored_opts)) {
            unsigned int day = (unsigned int)
                (time(NULL) / SECONDS_IN_DAY);
	    uint32_t val = HAVE_OPT(REHASH) ? OPT_VALUE_REHASH : OPT_VALUE_PBKDF2;
            fprintf(fp, pwid_pbkdf2_fmt, mark, day, val);
        }

        if (STATE_OPT(SPECIALS) == OPTST_DEFINED)
            fprintf(fp, pwid_specials_fmt, mark, OPT_ARG(SPECIALS));

        if (ENABLED_OPT(SHARED))
            fprintf(fp, pwid_second_fmt, mark);

        fclose(fp);
    }
}

/**
 * Remove the password id \a name.
 * @param name  the name/id for which a password is needed
 */
static void
remove_pwid(char const * name)
{
    fwrite(rm_entry, rm_entry_LEN, 1, stdout);
    print_pwid_status(name);
    {
        bool         found    = false;
        size_t       mark_len;
        char *       mark     = make_pwid_mark(name, &mark_len);
        char *       scan     = config_file_text;

        while (scan = strstr(scan, mark),
               scan != NULL) {
            char * sol = scan;
            found = true;

        find_next_tag_end:

            /*
             * If we can't find a tag end marker, truncate the file here.
             */
            scan = strstr(scan + mark_len, pwtag_z);
            if (scan == NULL) {
                *sol = NUL;
                break;
            }

            if (   (scan[pwtag_z_LEN] == NL)
                && (strncmp(scan + pwtag_z_LEN + 1, mark, mark_len) == 0))
                {
                    scan += pwtag_z_LEN + 1;
                    goto find_next_tag_end;
                }

            memmove(sol, scan, strlen(scan) + 1);
            scan = sol;
        }

        if (found) {
            char const * fnm = access_config_file();
            FILE * fp = fopen(fnm, "w");

            if (fp == NULL)
                fserr(GNU_PW_MGR_EXIT_NO_CONFIG, fopen_z, fnm);

            fputs(config_file_text, fp);
            fclose(fp);
        }
    }
}

/**
 * Insert two options:  --load-opts and --no-load-opts.
 * The former specifies the config file we decided upon,
 * and the latter disables the processing of any other config files.
 * When the option processing is done, we'll choke and die if any other
 * config files got loaded.
 *
 * @param ac  pointer to argc argument to main
 * @param av  pointer to argv argument to main
 */
static void
insert_load_opts(int * ac, char *** av)
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

/**
 * fix up the options. If there is a "--config-file" option, we leave
 * everything alone. Otherwise, we insert our own "--load-opts" and
 * disable user's use of that option.
 *
 * @param ac  pointer to argc argument to main
 * @param av  pointer to argv argument to main
 */
static void
create_cfg_file(char * opt, char * opt1)
{
    struct stat sb;
    int fno;

    opt = strchr(opt, '=');
    opt = (opt == NULL)
        ? opt1
        : opt + 1;

    set_config_name(opt);
    if (stat(opt, &sb) == 0)
        return;

    fno = open(opt, O_CREAT|O_WRONLY, S_IRWXU);
    if (fno < 0)
        fserr(GNU_PW_MGR_EXIT_INVALID, "open(O_CREAT)", opt);

    if (fchmod(fno, S_IRUSR | S_IWUSR) != 0)
        fserr(GNU_PW_MGR_EXIT_INVALID, "chmod", opt);

    fno = close(fno);
    if (fno != 0)
        fserr(GNU_PW_MGR_EXIT_INVALID, "close", opt);
}

/**
 * fix up the options. If there is a "--config-file" option, we leave
 * everything alone. Otherwise, we insert our own "--load-opts" and
 * disable user's use of that option.
 *
 * @param ac  pointer to argc argument to main
 * @param av  pointer to argv argument to main
 */
static void
fix_options(int * ac, char *** av)
{
    int     argc  = *ac;
    char ** argv  = *av;
    while (--argc > 0) {
        char * a = *++argv;
        int    c = strncmp(a, dash_config_z, dash_config_z_LEN);
        if (c == 0) {
            create_cfg_file(a, argv[1]);
            return;
        }
    }
    insert_load_opts(ac, av);
}

/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * indent-tabs-mode: nil
 * End:
 * end of pw-opts.c */
