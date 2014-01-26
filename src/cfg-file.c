/*
 *  This file is part of gpw.
 *
 *  Copyright (C) 2013-2014 Bruce Korb, all rights reserved.
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
        die(GNU_PW_MGR_EXIT_NO_CONFIG_INPUT, inv_cfg_perms,
            (unsigned int)(sbf.st_mode & secure_mask));

    config_file_size = sbf.st_size;
            
    chmod(config_file_name, S_IWUSR | S_IRUSR);

    return config_file_name;
}

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
 * Set the mode bits to user read only.  Group and other access disabled.
 */
static void
secure_cfg_file(void)
{
    if (config_file_name != NULL)
        (void)chmod(config_file_name, S_IRUSR);
}

/**
 * return the pointer to the configuration file text.
 * If already loaded, just return the address.  Otherwise,
 * read in all the text into allocated memory.
 *
 * @returns pointer to NUL-terminated, allocated, immutable text.
 */
static char const *
load_config_file(void)
{
    static char empty[] = "";
    static char const * config_file_data = empty;

    char * dta;
    if (config_file_data != empty)
        free((void *)config_file_data);
    
    (void) access_config_file();
    if (config_file_size == 0) {
        config_file_data = empty;
        return config_file_data;
    }

    config_file_data = dta = malloc(config_file_size + 1);

    if (dta == NULL)
        nomem_err(config_file_size, "config file data");
    {
        FILE * fp = fopen(config_file_name, "r");
        size_t sz = config_file_size;

        if (fp == NULL)
            fserr(GNU_PW_MGR_EXIT_NO_CONFIG, fopen_z, config_file_name);

        for (;;) {
            int ct = fread(dta, 1, sz, fp);
            if (ct <= 0)
                fserr(GNU_PW_MGR_EXIT_NO_CONFIG, fread_z, config_file_name);
            sz -= ct;
            if (sz == 0)
                break;
            dta += ct;
        }
    }

    dta[config_file_size] = NUL;
    return config_file_data;
}

#define config_file_name config_file_name used in invalid context
#define config_file_size config_file_size used in invalid context

/**
 * Find the user's home directory.  There are two implementations.
 * When the TEST_GPW preprocessing macro is defined, the home
 * directory is gotten from the TEST_HOME environment variable.
 * Normally, it is gotten from the password entry for the current user.
 *
 * This presumes getpwuid() works.  If not, then getenv("HOME") is used.
 *
 * @returns an allocated string with the home directory path.
 * It should not be deallocated.
 */
static char const *
find_home(void)
{
    char const * res;

# if defined(TEST_GPW)
    static char const test_home[] = "TEST_HOME";
    res = getenv(test_home);

# elif defined(HAVE_GETPWUID)
    struct passwd * pwd = getpwuid(getuid());
    if (pwd == NULL)
        die(GNU_PW_MGR_EXIT_HOMELESS, no_pwent, (unsigned int)getuid());
    res = strdup(pwd->pw_dir);

# else
    res = strdup(getenv("HOME"));
# endif
    if (res == NULL)
        die(GNU_PW_MGR_EXIT_NO_MEM, no_mem_4_home);

    return res;
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

    char const * home = find_home();
    struct stat sbf;
    size_t fname_len = home_cfg_LEN + local_cfg_LEN + local_dir_LEN + 3;

    if (  (home == NULL)
       || (stat(home, &sbf) != 0)
       || (! S_ISDIR(sbf.st_mode)))

        die(GNU_PW_MGR_EXIT_HOMELESS, no_home);

    fname = xscribble_get(fname_len + strlen(home));

    /*
     * fname is now allocated to the size we need.
     * now fill it in
     */
    fname_len =  strlen(home);
    memcpy(fname, home, fname_len);
    fname[fname_len++] = '/';
    memcpy(fname + fname_len, local_dir, local_dir_LEN + 1);

    /*
     * If there is a ~/.local directory, use it.  The file name varies based
     * on whether $HOME or $HOME/.local is used.
     */
    if ((stat(fname, &sbf) != 0) || ! S_ISDIR(sbf.st_mode)) {
        home = home_cfg;

    } else {
        home = local_cfg;

        if ((sbf.st_mode & secure_mask) != 0)
            die(GNU_PW_MGR_EXIT_PERM, cfg_insecure, fname);

        fname_len += local_dir_LEN;
        fname[fname_len++] = '/';
    }

    /*
     * Ensure it is properly secured.
     */
    strcpy(fname + fname_len, home);
    if (stat(fname, &sbf) != 0) {
        int fd;
        if (errno != ENOENT)
            die(GNU_PW_MGR_EXIT_NO_CONFIG, cfg_missing_fmt, fname);
        fd = open(fname, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
        if ((fd < 0) || (close(fd) < 0))
            fserr(GNU_PW_MGR_EXIT_NO_CONFIG, open_z, fname);
        chmod(fname, S_IRUSR | S_IWUSR);

    } else if ((sbf.st_mode & secure_mask) != 0)
        die(GNU_PW_MGR_EXIT_PERM, cfg_insecure, fname);

    set_config_name(fname);
    return fname;
}
