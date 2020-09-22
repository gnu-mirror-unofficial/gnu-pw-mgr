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

/**
 * load the domain file.
 * The buffer allocated for it is big enough for all the text,
 * plus a NUL byte then rounded up to a multiple of 4096.
 *
 * @param fname the name of the domain name file
 */
static char *
load_domain_file(char const * fname)
{
    char * txt;
    char * scn;
    size_t sz;
    FILE * fp;

    if (stat(fname, &dom_file_stat) != 0) {
        if (errno != ENOENT)
            fserr(GNU_PW_MGR_EXIT_INVALID, "stat", fname);
        dom_file_stat.st_size = 4096;
        txt = malloc(dom_file_stat.st_size);
        txt[0] = NUL;
        return txt;
    }

    if (! S_ISREG(dom_file_stat.st_mode)) {
        errno = EINVAL;
        fserr(GNU_PW_MGR_EXIT_INVALID, "stat", fname);
    }
    fp  = fopen(fname, "r");
    if (fp == NULL)
        fserr(GNU_PW_MGR_EXIT_INVALID, "fopen 'r'", fname);
    sz  = (dom_file_stat.st_size + 4096) & ~4096;
    txt = scn = malloc(sz);
    for (;;) {
        size_t rdsz = fread(scn, 1, dom_file_stat.st_size, fp);
        if (rdsz == 0)
            break;
        scn += rdsz;
        dom_file_stat.st_size -= rdsz;
        if (dom_file_stat.st_size == 0)
            break;
    }
    *scn = NUL;
    dom_file_stat.st_size = sz;
    dom_text_len          = (scn - txt);
    dom_text = txt;
    fclose(fp);
    return txt;
}

/**
 * List the domains in the domain file.
 */
static void
list_domains(void)
{
    if (dom_text == NULL)
        (void) load_domain_file(dom_file_name);
    fwrite(dom_text, 1, dom_text_len, stdout);
}

/**
 * List the domains in the domain file.
 */
static void
write_dom_file(void)
{
    FILE * fp;
    if (dom_text_len == 0)
        return;

    fp = fopen(dom_file_name, "w");
    if (fp == NULL)
        fserr(GNU_PW_MGR_EXIT_INVALID, "fopen 'w'", dom_file_name);
    size_t wrlen = fwrite(dom_text, 1, dom_text_len, fp);
    if (wrlen != dom_text_len)
        fserr(GNU_PW_MGR_EXIT_INVALID, "fwrite", dom_file_name);
    fclose(fp);
}

/**
 * Insert a new domain name or update its access date.
 *
 * @param dom new domain name
 */
static void
insert_domain(char const * dom)
{
    static char const end_dom_mark[]  = "</domain>\n";
    static char const dom_entry_fmt[] = "<domain time=%-10.10lu%s";
    static unsigned long const secs_per_day = 60UL * 60UL * 24UL;
    static size_t base_size = sizeof(end_dom_mark) + sizeof(dom_entry_fmt);

    char buf[256] = ">";
    size_t dom_len = strlen(dom);
    unsigned long cap_time = (unsigned long)time(NULL) / secs_per_day;
    if (dom_len + sizeof(end_dom_mark) + 1 > sizeof(buf))
        return;

    if (dom_text == NULL)
        (void) load_domain_file(dom_file_name);
    memcpy(buf+1, dom, dom_len);
    memcpy(buf + 1 + dom_len, end_dom_mark, sizeof(end_dom_mark));

    char * dom_entry = strstr(dom_text, buf);

    /*
     * IF we have this domain already, then
     */
    if (dom_entry != NULL) {
        dom_entry -= 10;
        int ct = sprintf(dom_entry, "%-10.10lu", cap_time);
        assert(ct == 10);
        dom_entry[10] = '>';

    } else {
        if ((dom_text_len + dom_len + base_size) >= dom_file_stat.st_size) {
            dom_file_stat.st_size += 4096;
            dom_text = realloc(dom_text, dom_file_stat.st_size);
            if (dom_text == NULL) {
                sprintf(buf, "%lu", (unsigned long) dom_file_stat.st_size);
                fserr(GNU_PW_MGR_EXIT_NO_MEM, "realloc", buf);
            }
        }
        dom_entry = dom_text + dom_text_len;
        dom_text_len += sprintf(dom_entry, dom_entry_fmt, cap_time, buf);
    }
}

/**
 * Figure out the name of the domain name file.
 * See find_cfg_name() above.
 *
 * @returns  the name in a scribble buffer.  Copy it out to save it.
 */
static char *
find_dom_file(void)
{
    if (HAVE_OPT(CONFIG_FILE)) {
        (void)set_cfg_dir(NULL);
        return strdup(OPT_ARG(CONFIG_FILE));
    }

    {
        bool   have_local;
        char * fname     = set_cfg_dir(&have_local);
        size_t fname_len = strlen(fname);

        strcpy(fname + fname_len, have_local ? local_dom : home_dom);
        return fname;
    }
}

/**
 * Process domain name option.
 */
static void
proc_dom_opts(int rem_arg_ct)
{
    int  ct = STACKCT_OPT(DOMAIN);
    char const ** dom_list = STACKLST_OPT(DOMAIN);
    bool list_doms = false;
    bool new_entry = false;

    dom_file_name = find_dom_file();
    dom_text = load_domain_file(dom_file_name);

    do {
        char const * dom = *(dom_list++);
        if ((*dom == '-') && (dom[1] == NUL))
            list_doms = true;

        else {
            insert_domain(dom);
            new_entry = true;
        }
    } while (--ct > 0);

    if (new_entry)
        write_dom_file();

    if (list_doms)
        list_domains();
    if (rem_arg_ct <= 0)
        exit(GNU_PW_MGR_EXIT_SUCCESS);
}

/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * indent-tabs-mode: nil
 * End:
 * end of domains.c */
