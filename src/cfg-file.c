/**
 * @file cfg-file.c
 *
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

////PULL-HEADERS:

#ifndef MAXPATHLEN
# define MAXPATHLEN 4096
#endif
#define MAX_CFG_NAME_SIZE 32

#ifndef SORT_PW_CFG // code for gnu-pw-mgr only

/**
 * Set the name of the configure file.
 * @param[in] nm  name to set it to
 */
static void
set_config_name(char const * nm)
{
    config_file_name = strdup(nm);
    if (config_file_name == NULL)
        nomem_err(strlen(nm), "file name");
}

/**
 * Gain access to the config file.  \a set_config_name must have been
 * called previously.  This function figures out the current size and
 * ensures we can read and write the thing.  It also ensures that
 * nobody else can read or write the thing.
 *
 * @returns the file name as a constant string
 */
static char const *
access_config_file(void)
{
    struct stat sbf;

    if (config_file_name == NULL)
        die(GNU_PW_MGR_EXIT_CODING_ERROR, acc_b4_set);

    if (stat(config_file_name, &sbf) != 0)
        die(GNU_PW_MGR_EXIT_NO_CONFIG, cannot_stat_cfg, config_file_name);
    if ((sbf.st_mode & secure_mask) != 0)
        die(GNU_PW_MGR_EXIT_PERM, inv_cfg_perms, config_file_name,
            (unsigned int)(sbf.st_mode & 0777));

    config_file_size = sbf.st_size;

    if (chmod(config_file_name, S_IWUSR | S_IRUSR) != 0)
        fserr(GNU_PW_MGR_EXIT_BAD_CONFIG, cfg_immutable, config_file_name);

    return config_file_name;
}

/**
 * Set the mode bits to user read only.  Group and other access disabled.
 */
static void
secure_cfg_file(void)
{
    if (config_file_name != NULL)
        (void)chmod(config_file_name, S_IRUSR);
}

/**
 * load the configuration file into memory and set the global variable
 * @config_file_text to point to it.
 */
static void
load_config_file(void)
{
    if (config_file_text != empty_config_data)
        free((void *)config_file_text);

    (void) access_config_file();
    if (config_file_size == 0) {
        config_file_text = (char *)(void *)empty_config_data;
        return;
    }

    {
        FILE * fp  = fopen(config_file_name, "r");
        size_t sz  = config_file_size;
        char * dta = config_file_text = malloc(config_file_size + 1);

        if (fp == NULL)
            fserr(GNU_PW_MGR_EXIT_NO_CONFIG, fopen_z, config_file_name);

        if (dta == NULL)
            nomem_err(config_file_size, "config file data");

        for (;;) {
            int ct = fread(dta, 1, sz, fp);
            if (ct <= 0)
                fserr(GNU_PW_MGR_EXIT_NO_CONFIG, fread_z, config_file_name);
            sz -= ct;
            if (sz == 0)
                break;
            dta += ct;
        }

        dta[config_file_size] = NUL;
    }
}

#endif // not SORT_PW_CFG only

/**
 * Find the user's home directory.  If the --seed-file option is present,
 * we'll just use the directory portion of that name.
 *
 * This presumes getpwuid() works.  If not, then getenv("HOME") is used.
 *
 * @returns an allocated string with the home directory path.
 * It should not be deallocated.
 */
static char const *
find_home_dir(void)
{
    char const * res;
    struct stat sbf;

#ifndef SORT_PW_CFG // no --config-file option for sort
    if (HAVE_OPT(CONFIG_FILE)) {
        char * p = strdup(OPT_ARG(CONFIG_FILE));
        if (p == NULL)
            nomem_err(strlen(OPT_ARG(CONFIG_FILE)), "file name");

        res = p;
        p = strrchr(p, '/');
        /*
         * If there is no directory separator, we'll use the current directory.
         */
        if (p != NULL)
            *p = NUL;
        else {
            p = (char *)(intptr_t)res;
            strcpy(p, ".");
        }
    }
    else
#endif // SORT_PW_CFG not defined

    {
# if defined(HAVE_GETPWUID)
        struct passwd * pwd = getpwuid(getuid());
        if (pwd == NULL)
            die(GNU_PW_MGR_EXIT_HOMELESS, no_pwent_fmt, (unsigned int)getuid());
        res = strdup(pwd->pw_dir);

# else
        res = strdup(getenv("HOME"));
        if (res == NULL)
            die(GNU_PW_MGR_EXIT_HOMELESS, no_home);
# endif
    }

    if (  (stat(res, &sbf) != 0)
       || (! S_ISDIR(sbf.st_mode)))

        die(GNU_PW_MGR_EXIT_HOMELESS, no_home);

    return res;
}

/**
 * Search one directory for our config file
 *
 * @param[in]  home           the config file home directory (maybe)
 * @param[out] used_cfg_name  whether cfg_name or rc_name was used
 * @param[in]  check_cfg_file whether we can stop hunting without a config file
 *
 * @returns a buffer with the config file home directory name but also
 *          with enough space in it to append the config file name.
 */
static char *
check_home_dir(char const * home, bool * used_cfg_name, bool check_cfg_file)
{
    char name_buf[MAXPATHLEN];
    struct stat sbf;
    char * suffix;
    size_t home_len = strlen(home);
    bool   use_cfg_name = false;

    if ((stat(home, &sbf) != 0) || ! S_ISDIR(sbf.st_mode))
        return NULL;

    memcpy(name_buf, home, home_len);
    suffix = name_buf + home_len;

    /*
     * IF we are looking at the real home directory, check for a ".local"
     * subdirectory. If it is there, always append it and use that.
     */
    if (home != home_dirs[HOME_DIR_IX])
        use_cfg_name = true;
    else
        do {
            strcpy(suffix, local_dir);
            if (stat(name_buf, &sbf) != 0)
                break; // No such name

            if (! S_ISDIR(sbf.st_mode))
                break; // Not a directory

            /*
             * Make sure directory permissions are correct
             */
            if ((sbf.st_mode & secure_mask) != 0)
                die(GNU_PW_MGR_EXIT_PERM, inv_cfg_perms, home,
                    (unsigned int)(sbf.st_mode & 0777));

            /*
             * Incorporate ".local" into the name
             */
            suffix += local_dir_LEN;
            use_cfg_name = true;
        } while (false);

    /*
     * See if the config file exists in the directory.
     * if it does not, this is only correct when we are planting
     * a new seed (which never happens with sort-pw-cfg).
     */
    *(suffix++) = '/';
    strcpy(suffix, use_cfg_name ? cfg_fname : rc_fname);
    if (stat(name_buf, &sbf) != 0) {

        /*
         * IF we can't find the config file, tell our caller to keep
         * trying in case another directory has the config file.
         */
        if (! check_cfg_file)
            return NULL;

#ifndef SORT_PW_CFG
        if (HAVE_OPT(SEED))
            goto dir_checks_out;
        /*
         * We're not adding a seed so we cannot be creating a new
         * config file, but we can't find one either. Keep looking.
         */
#endif // ! SORT_PW_CFG

        return NULL;
    }

    /*
     * Make sure the file is properly secured. (only read and only by user)
     */
    if ((sbf.st_mode & (secure_mask | S_IWUSR | S_IXUSR)) != 0)
        die(GNU_PW_MGR_EXIT_PERM, inv_cfg_perms, name_buf,
            (unsigned int)(sbf.st_mode & 0777));

dir_checks_out:

    {
        char * res;
        home_len = suffix - name_buf;
        res = xscribble_get(home_len + MAX_CFG_NAME_SIZE);
        memcpy(res, name_buf, home_len);
        res[home_len]  = NUL; // leave trailing slash
        *used_cfg_name = use_cfg_name;
        return res;
    }
}

#ifdef __apple__
/**
 * Search in Apple's favorite place to stash config files.
 */
static void
find_apple_cfg_dir(void)
{
    size_t hd_len = strlen(home_dirs[HOME_DIR_IX]);
    char * p;
    {
        size_t buf_sz = hd_len + apple_cfg_dir_LEN + MAX_CFG_NAME_SIZE;
        p      = malloc(buf_sz);
        if (p == NULL)
            nomem_err(buf_sz, "file name");
    }
    home_dirs[APPLE_LOCAL_IX] = p;
    memcpy(p, home_dirs[HOME_DIR_IX], hd_len);

    /*
     * Copy in the directory name with the terminating NUL.
     */
    p += hd_len;
    memcpy(p, apple_cfg_dir, apple_cfg_dir_LEN + 1);
    p = strrchr(p, '/');
    if (p == NULL)
        die(GNU_PW_MGR_EXIT_CODING_ERROR, bad_apple_cfgd);

    {
        struct stat sbf;

        /*
         * Remove the last name in the path and verify we have a directory,
         * then restore the directory separator
         */
        *p = NUL;
        if (  (stat(home_dirs[APPLE_LOCAL_IX], &sbf) != 0)
           || (! S_ISDIR(sbf.st_mode)))

            die(GNU_PW_MGR_EXIT_HOMELESS, no_apple_cfgd, apple_cfg_dir);
        *p = '/';

        /*
         * The full path must exist and be a directory, or else
         * we have to be able to create that directory.
         */
        if (stat(home_dirs[APPLE_LOCAL_IX], &sbf) == 0) {
            if (! S_ISDIR(sbf.st_mode))
                die(GNU_PW_MGR_EXIT_NO_CONFIG,
                    no_apple_cfgd, apple_cfg_dir);
        } else {
            if (mkdir(home_dirs[APPLE_LOCAL_IX], 0700) != 0)
                fserr(GNU_PW_MGR_EXIT_BAD_CONFIG, mkdir_z,
                      home_dirs[APPLE_LOCAL_IX]);
        }
    }
}
#endif // __apple__

/**
 * figure out where the config file has to live
 *
 * @param[out] used_cfg_name boolen to tell caller whether to use .xxxrc
 *                        or xxx.cfg format
 *
 * @returns a scribble buffer with the directory name in it
 */
static char *
set_cfg_dir(bool * used_cfg_name)
{
    char * fname;
    home_ix_t hix;

    home_dirs[HOME_DIR_IX] = find_home_dir();

#ifndef SORT_PW_CFG
    if (HAVE_OPT(CONFIG_FILE)) {
        size_t l = strlen(OPT_ARG(CONFIG_FILE)) + 1;
        fname = xscribble_get(l + MAX_CFG_NAME_SIZE);
        strcpy(fname, home_dirs[HOME_DIR_IX]);
        return fname;
    }
#endif // ! SORT_PW_CFG

    home_dirs[XDG_DATA_HOME_IX]   = getenv("XDG_DATA_HOME");
    home_dirs[XDG_CONFIG_HOME_IX] = getenv("XDG_CONFIG_HOME");
#ifdef __apple__
    find_apple_cfg_dir();
#endif //  __apple__

    for (hix = HOME_IX_CT; hix-- != 0;) {
        char const * hd = home_dirs[hix];
        if (hd == NULL)
            continue;

        /*
         * The "false" parameter says we want to look in all the
         * directories for a config file.
         */
        fname = check_home_dir(hd, used_cfg_name, false);
        if (fname != NULL)
            return fname;
    }

    /*
     * We searched the standard directories for our config file,
     * but we couldn't find it. So, we must be creating it.
     * But if we don't have a --seed option, then we cannot,
     * so quit now.
     */
#ifdef SORT_PW_CFG
    die(GNU_PW_MGR_EXIT_NO_CONFIG, cfg_missing_fmt,
        *used_cfg_name ? cfg_fname : rc_fname);
#else
    if (! HAVE_OPT(SEED))
        die(GNU_PW_MGR_EXIT_NO_CONFIG, cfg_missing_fmt,
            *used_cfg_name ? cfg_fname : rc_fname);

    for (hix = HOME_IX_CT; hix-- != 0;) {
        char const * hd = home_dirs[hix];
        if (hd == NULL)
            continue;

        /*
         * The "true" parameter says we want to stop looking as soon
         * as we find an acceptable directory.
         */
        fname = check_home_dir(hd, used_cfg_name, true);
        if (fname != NULL)
            return fname;
    }
    die(GNU_PW_MGR_EXIT_NO_CONFIG, cfg_missing_fmt, fname);
#endif // ! SORT_PW_CFG
}

/**
 * Figure out the name of the config file.  If ~/.local/ exists, we look there.
 * If not, we use ~/.gnupwmgrrc.
 *
 * @returns  the name in a scribble buffer.  Copy it out to save it.
 */
static char *
find_cfg_name(void)
{
    char * fname;
    size_t fname_len;

#ifndef SORT_PW_CFG
    if (HAVE_OPT(CONFIG_FILE)) {
        char const * fn = OPT_ARG(CONFIG_FILE);
        (void)set_cfg_dir(NULL);
        fname_len = strlen(fn) + 1;
        fname     = xscribble_get(fname_len);
        strcpy(fname, fn);
    }
    else
#endif // ! SORT_PW_CFG

    {
        bool        used_cfg_name;
        struct stat sbf;

        fname     = set_cfg_dir(&used_cfg_name);
        fname_len = strlen(fname);

        /*
         * Ensure it is properly secured.
         */
        strcpy(fname + fname_len, used_cfg_name ? cfg_fname : rc_fname);
        if (stat(fname, &sbf) != 0) {
            int fd;
            if (errno != ENOENT)
                die(GNU_PW_MGR_EXIT_NO_CONFIG, cfg_missing_fmt, fname);
            fd = open(fname, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
            if ((fd < 0) || (close(fd) < 0))
                fserr(GNU_PW_MGR_EXIT_NO_CONFIG, open_z, fname);
            chmod(fname, S_IRUSR | S_IWUSR);

        } else if ((sbf.st_mode & secure_mask) != 0)
            die(GNU_PW_MGR_EXIT_PERM, inv_cfg_perms, fname,
                (unsigned int)(sbf.st_mode & 0777));
    }

    set_config_name(fname);
    return fname;
}

/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * indent-tabs-mode: nil
 * End:
 * end of cfg-file.c */
