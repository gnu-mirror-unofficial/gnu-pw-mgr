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

////PULL-HEADERS:

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
#endif // SORT_PW_CFG defined

    {
# if defined(HAVE_GETPWUID)
        struct passwd * pwd = getpwuid(getuid());
        if (pwd == NULL)
            die(GNU_PW_MGR_EXIT_HOMELESS, no_pwent, (unsigned int)getuid());
        res = strdup(pwd->pw_dir);

# else
        res = strdup(getenv("HOME"));
        if (res == NULL)
            die(GNU_PW_MGR_EXIT_HOMELESS, no_pwent, (unsigned int)getuid());
# endif
    }

    if (  (stat(res, &sbf) != 0)
       || (! S_ISDIR(sbf.st_mode)))

        die(GNU_PW_MGR_EXIT_HOMELESS, no_home);

    return res;
}

static char *
set_cfg_dir(bool * have_local)
{
    char * fname;

    home_dirs[HOME_DIR_IX]        = find_home_dir();
    home_dirs[XDG_DATA_HOME_IX]   = getenv("XDG_DATA_HOME");
    home_dirs[XDG_CONFIG_HOME_IX] = getenv("XDG_CONFIG_HOME");

    struct stat sbf;
    size_t fname_len = home_cfg_LEN + local_cfg_LEN + local_dir_LEN + 3;

#ifndef SORT_PW_CFG
    if (HAVE_OPT(CONFIG_FILE)) {
        size_t l = strlen(OPT_ARG(CONFIG_FILE)) + 1;
        fname = xscribble_get(l);
        strcpy(fname, home_dirs[HOME_DIR_IX]);
        return fname;
    }
#endif // ! SORT_PW_CFG

    fname = xscribble_get(fname_len + strlen(home_dirs[HOME_DIR_IX]));

    /*
     * fname is now allocated to the size we need.
     * now fill it in
     */
    fname_len =  strlen(home_dirs[HOME_DIR_IX]);
    memcpy(fname, home_dirs[HOME_DIR_IX], fname_len);
    fname[fname_len++] = '/';
    memcpy(fname + fname_len, local_dir, local_dir_LEN + 1);

    /*
     * If there is a ~/.local directory, use it.  The file name varies based
     * on whether $HOME or $HOME/.local is used.
     */
    if ((stat(fname, &sbf) != 0) || ! S_ISDIR(sbf.st_mode)) {
        *have_local = false;

    } else {
        *have_local = true;

        if ((sbf.st_mode & secure_mask) != 0)
            die(GNU_PW_MGR_EXIT_PERM, inv_cfg_perms, fname,
                (unsigned int)(sbf.st_mode & 0777));

        fname_len += local_dir_LEN;
        fname[fname_len++] = '/';
    }

    fname[fname_len] = NUL;
    return fname;
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
        bool        have_local;
        struct stat sbf;

        fname     = set_cfg_dir(&have_local);
        fname_len = strlen(fname);
    
        /*
         * Ensure it is properly secured.
         */
        strcpy(fname + fname_len, have_local ? local_cfg : home_cfg);
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
