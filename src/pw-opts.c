/*
 *  This file is part of gnu-pw-mgr.
 *
 *  Copyright (C) 2013-2018 Bruce Korb, all rights reserved.
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

#include <fcntl.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

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
 * set the options for a particular password id.
 * It modifies the \a optCookie field of \a DESC(CCLASS).
 *
 * @param[in]  pw_id   the password id
 */
static void
set_pwid_opts(char const * pw_id)
{
    char const * cfg_text = load_config_file();
    bool stored_option    = false; // true -> we found a saved option

    /*
     * Find the marker that separates the seeds from the
     * password id options
     */
    char const * scan = strstr(cfg_text, pw_id_tag);

    if (HAVE_OPT(REHASH)) {
	rehash_date = pw_today;
	OPT_VALUE_PBKDF2 = OPT_VALUE_REHASH;
    }

    if (scan != NULL) {
        size_t mark_len;
        char * mark = make_pwid_mark(pw_id, &mark_len);

        scan += pw_id_tag_LEN;

        for (;;) {
            char * end;
            char * opt_text;
            size_t text_len;

            scan = next_pwid_opt(scan, mark, mark_len);
            if (scan == NULL)
                break;

	    stored_option = true;
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

    {
	bool save_cclass_opt = false;

	/*
	 * If we have a default character class and we did not find
	 * any stored options for this password id, then set the
	 * caracter classes to the default and note that we must
	 * rewrite the cclass option. (Setting state to "DEFINED"
	 * tells the wrap up code that the value must be saved.)
	 */
	if (HAVE_OPT(DEFAULT_CCLASS) && (! stored_option)) {
	    SET_OPT_CCLASS((uintptr_t) (void*) OPT_ARG(DEFAULT_CCLASS));
	    save_cclass_opt = true;
	}

	sanity_check_cclass();

	if (save_cclass_opt) {
	    DESC(CCLASS).fOptState &= OPTST_PERSISTENT_MASK;
	    DESC(CCLASS).fOptState |= OPTST_DEFINED;
	}
    }
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
        char * popt = strstr(buf, mark);
        char * p    = popt;

        if (p == NULL)
            return;

        /*
         * The marker may have more than just <pwtag id="..">, so
         * scan over whatever else and past the closing '>'.
         */
        p = strchr(p, '>');
        if (p == NULL)
            return;

        /*
         * Convert the next part into the option type enumeration
         * and see if it matches the one we're looking for.
         * Spellings are "allowed" to vary, so it's not just a
         * strncmp().
         */
        if (find_set_opt_cmd(++p) == typ) {
            buf = popt;
            break;
        }
        buf = p + id_mark_end_LEN;
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

static bool
removed_old_opts(char const * cfg_text, char const * name, char ** mark_p)
{
    bool res = false;
    size_t mark_len;

    char * mark = *mark_p = make_pwid_mark(name, &mark_len);

    if (STATE_OPT(LOGIN_ID) == OPTST_DEFINED) {
        res = true;
        remove_opt(cfg_text, mark, mark_len, SET_CMD_LOGIN_ID);
    }

    if (STATE_OPT(LENGTH) == OPTST_DEFINED) {
        res = true;
        remove_opt(cfg_text, mark, mark_len, SET_CMD_LENGTH);
    }

    if (STATE_OPT(CCLASS) == OPTST_DEFINED) {
        res = true;
        remove_opt(cfg_text, mark, mark_len, SET_CMD_CCLASS);
    }
    if (HAVE_OPT(REHASH)) {
        res = true;
        remove_opt(cfg_text, mark, mark_len, SET_CMD_NO_PBKDF2);
        remove_opt(cfg_text, mark, mark_len, SET_CMD_USE_PBKDF2);
    }

    if (STATE_OPT(SPECIALS) == OPTST_DEFINED) {
        res = true;
        remove_opt(cfg_text, mark, mark_len, SET_CMD_SPECIALS);
    }

    if (STATE_OPT(SHARED) == OPTST_DEFINED) {
        res = true;
        remove_opt(cfg_text, mark, mark_len, SET_CMD_SHARED);
    }

    return res;
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

    if (! removed_old_opts(cfg_text, name, &mark))
        return;

    /*
     * We have new info to stash.  Any old values in "cfg_text"
     */
    {
        char const * fnm = access_config_file();
        FILE * fp = fopen(fnm, "w");

        if (fp == NULL)
            fserr(GNU_PW_MGR_EXIT_NO_CONFIG, fopen_z, fnm);

        fputs(cfg_text, fp);
        if (STATE_OPT(LOGIN_ID) == OPTST_DEFINED)
            fprintf(fp, pwid_login_id_fmt, mark, OPT_ARG(LOGIN_ID));

        if (STATE_OPT(LENGTH) == OPTST_DEFINED)
            fprintf(fp, pwid_length_fmt, mark, (unsigned int)OPT_VALUE_LENGTH);

        if (STATE_OPT(CCLASS) == OPTST_DEFINED) {
            tOptDesc *   od   = &DESC(CCLASS);
            char const * save = od->optArg.argString;
            doOptCclass(OPTPROC_RETURN_VALNAME, od);
            fprintf(fp, pwid_cclass_fmt, mark, od->optArg.argString);
            free((void *)od->optArg.argString);
            od->optArg.argString = save;
        }

	if (HAVE_OPT(REHASH)) {
            unsigned int day = (unsigned int)
                (time(NULL) / SECONDS_IN_DAY);

            fprintf(fp, pwid_pbkdf2_fmt, mark, day,
		    (uint32_t)OPT_VALUE_REHASH);
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
    print_pwid_status(name);
    {
        size_t       mark_len;
        char const * cfg_text = load_config_file();
        char *       scan     = strstr(cfg_text, pw_id_tag);
        char *       mark     = make_pwid_mark(name, &mark_len);
        bool         found    = false;

        if (scan == NULL)
            return;
        scan += pw_id_tag_LEN;

        while (scan = strstr(scan + 1, mark),
               scan != NULL) {
            char * sol = scan;
            found = true;

        find_line_end:

            scan = strstr(scan + mark_len, pwtag_z);
            if (scan == NULL) {
                *sol = NUL;
                break;
            }

            if (strncmp(scan, mark, mark_len) == 0)
                goto find_line_end;

            memmove(sol, scan, strlen(scan) + 1);
            scan = sol;
        }

        if (found) {
            char const * fnm = access_config_file();
            FILE * fp = fopen(fnm, "w");

            if (fp == NULL)
                fserr(GNU_PW_MGR_EXIT_NO_CONFIG, fopen_z, fnm);

            fputs(cfg_text, fp);
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
    static char const conf[] = "--config";
    int     argc  = *ac;
    char ** argv  = *av;
    while (--argc > 0) {
        char * a = *++argv;
        int    c = strncmp(a, conf, sizeof(conf) - 1);
        if (c == 0) {
            create_cfg_file(a, argv[1]);
            return;
        }
    }
    insert_load_opts(ac, av);
}
