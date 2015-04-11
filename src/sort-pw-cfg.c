
#define SORT_PW_CFG 1

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sort-opts.h"
#include "gpw-str.h"

#include "sort-opts.c"
#include "gpw-str.c"

#ifndef NUL
#define NUL '\0'
#endif

#ifndef NL
#define NL '\n'
#endif

typedef struct pw_opt_line pw_opt_line_t;

struct pw_opt_line {
    pw_opt_line_t * next;
    pw_opt_line_t * prev;
    char const *    line;
};

static pw_opt_line_t opt_hash[0x4000];

/*
 * This is a 16K entry hash table.  Collisions are unlikely, unless you
 * really have an awful lot of passwords you are maintaining.
 */
#define TXT_HASH(_s) ( \
    ((unsigned int)((_s)[0]) << 7) \
    + (unsigned int)((_s)[1])  )

static inline void
add_hash_entry(pw_opt_line_t * ol, char const * txt)
{
    static char const id_str[] = " id=\"";
    char const * hash_txt = strstr(txt, id_str);
    unsigned int hash_len;
    unsigned int off;

    if (hash_txt == NULL)
        return;

    hash_txt += sizeof(id_str) - 1;
    off = hash_txt - txt;

    {
        char const * equ = strchr(hash_txt, '=');
        if (equ == NULL)
            return;
        hash_len = equ - hash_txt;
    }

    {
        int hash_ix = TXT_HASH(hash_txt);
        pw_opt_line_t * olh = opt_hash + hash_ix;
        pw_opt_line_t * ole = olh->next;
        while (ole != olh) {
            if (strncmp(ole->line + off, hash_txt, hash_len) == 0) {
                ole->line = txt;
                return;
            }
            ole = ole->next;
        }

        ole = olh->next;
        ol->line  = txt;

        /*
         * Keep the list sorted.  We could have used a singly linked list...
         */
        while (ole != olh) {
            if (strncmp(ole->line + off, hash_txt, hash_len) > 0)
                break;
            ole = ole->next;
        }

        /*
         * Insert before the "ole" entry.
         */
        ol->next  = ole;
        ol->prev  = ole->prev;
        ole->prev->next = ol;
        ole->prev = ol;
    }
}

/**
 * parse each line of text
 * @param text  the start of the current line of text
 */
static inline void
parse_cfg_text(char * text)
{
    int ct = 0;
    {
        char * scan = strchr(text, NL);
        while (scan != NULL) {
            ct++;
            scan = strchr(scan + 1, NL);
        }
    }
    {
        pw_opt_line_t * opt_list = malloc(ct * sizeof(*opt_list));
        ct = 0;
        for (;;) {
            add_hash_entry(opt_list + (ct++), text);
            text = strchr(text, NL);
            if (text == NULL)
                break;
            *(text++) = NUL;
            text = strstr(text, pwtag_z);
            if (text == NULL)
                break;
        }
    }
}

/**
 * initialize the hash table and set the "config file name"
 * to that of the first config file (used for default output),
 * and remember the header block from that file.
 *
 * @param fname  name of the first config file
 * @param text   the header block from that file.
 */
static inline void
init_config_data(char const * fname, char * text)
{
    int ct = sizeof(opt_hash) / sizeof(opt_hash[0]);
    pw_opt_line_t * olh = opt_hash;

    config_file_name = fname;
    leader_text = text;
    do  {
        olh->next = olh->prev = olh;
        olh++;
    } while (--ct > 0);
}

/**
 * Load the domain-specific attributes from a config file.
 *
 * @param fname    name of the config file
 * @param text     the text in that file
 * @param text_sz  the size of that text
 */
int
load_domain_attrs(char const * fname, char * text, size_t text_sz)
{
    if (config_file_name == NULL)
        init_config_data(fname, text);

    text = strstr(text, pw_id_tag);
    if (text == NULL)
        die(SORT_PW_CFG_EXIT_INVALID, "config file %s missing id tag:  %s\n",
            fname, pw_id_tag);
    text += strlen(pw_id_tag);
    *(text++) = NUL;
    while (isspace(*text))
        text++;

    parse_cfg_text(text);

    return SORT_PW_CFG_EXIT_SUCCESS;
}


static inline FILE*
open_cfg_for_output(void)
{
    {
        struct stat sbf;
        if (config_file_name == NULL)
            die(SORT_PW_CFG_EXIT_NO_CONFIG, "no input config file");
        errno = 0;
        stat(config_file_name, &sbf);
        switch (errno) {
        case 0:
            if (access(config_file_name, W_OK) == 0)
                break;

            if (chmod(config_file_name, sbf.st_mode | S_IWUSR | S_IWGRP) != 0)
                fserr(SORT_PW_CFG_EXIT_BAD_CONFIG, cfg_immutable,
                      config_file_name);
        case ENOENT:
            break;

        default:
            die(SORT_PW_CFG_EXIT_NO_CONFIG, cannot_stat_cfg, config_file_name);
            /* NOTREACHED */
        }
    }

    {
        FILE * fp = fopen(config_file_name, "w");
        if (fp == NULL)
            fserr(SORT_PW_CFG_EXIT_BAD_CONFIG, cfg_immutable,
                  config_file_name);
        return fp;
    }
}

sort_pw_cfg_exit_code_t
emit_new_text(void)
{
    FILE * fp;

    if (! HAVE_OPT(OUTPUT)) {
        fp = open_cfg_for_output();

    } else {
        if (  (access(OPT_ARG(OUTPUT), W_OK) != 0)
           && (errno != ENOENT)) {
            if (chmod(OPT_ARG(OUTPUT), S_IWUSR | S_IRUSR) != 0)
                fserr(SORT_PW_CFG_EXIT_BAD_CONFIG, cfg_immutable,
                      OPT_ARG(OUTPUT));
        }

        fp = fopen(OPT_ARG(OUTPUT), "w");
        if (fp == NULL)
            fserr(SORT_PW_CFG_EXIT_BAD_CONFIG, cfg_immutable,
                  OPT_ARG(OUTPUT));
    }

    fputs(leader_text, fp);
    fputc(NL, fp);

    {
        pw_opt_line_t * olh = opt_hash;
        int ix = sizeof(opt_hash) / sizeof(opt_hash[0]);

        do  {
            pw_opt_line_t * ole = olh->next;
            while (ole != olh) {
                fputs(ole->line, fp);
                fputc(NL, fp);
                ole = ole->next;
            }
            olh++;
        } while (--ix > 0);
    }

    fchmod(fileno(fp), S_IRUSR);
    fclose(fp);
    return SORT_PW_CFG_EXIT_SUCCESS;
}
