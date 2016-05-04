/*
 *  This file is part of gpw.
 *
 *  Copyright (C) 2013-2015 Bruce Korb, all rights reserved.
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
 * set a new random seed for seed text padding.  This is done every
 * 16 bytes of padding.  Otherwise, a fully padded 64 byte seed text
 * would only have 32,000 variations.  Reading the random device
 * 64 times uses up too much of the entropy for a smallish gain.
 *
 * @param[in] wiggle  if there is no random device, then wiggle the
 * time a little bit.  time() will likely return the same second
 * every time, so alter this unpredictable seed a little bit to
 * make its predictability a bit more difficult.
 */
static void
randomize_seed(int wiggle)
{
    int fd = open(NAME_OF_RANDOM_DEVICE, O_RDONLY);
    unsigned int srand_seed = 0;
    if (fd < 0) {
        srand_seed = (int) time(NULL) + wiggle;
    } else {
        if (read(fd, &srand_seed, sizeof(srand_seed)) != sizeof(srand_seed))
            srand_seed = (int) time(NULL) + wiggle;
        close(fd);
    }
    srand(srand_seed);
}

/**
 * Ensure 64 bytes of seed text.  Anything less gets padded out with
 * random characters.
 *
 * @returns the seed text.
 */
static char const *
get_seed_text(void)
{
    char const * res = OPT_ARG(TEXT);
    size_t text_len  = strlen(res);
    if (text_len >= MIN_SEED_TEXT_LEN)
        return res;

    randomize_seed(0);

    {
        char * new_txt = malloc(128);
        if (new_txt == NULL)
            nomem_err(128, "seed");
        if (text_len == 0) {
            res = new_txt;
        } else {
            memcpy(new_txt, res, text_len);
            res = new_txt;
            new_txt += text_len;
        }
        text_len = MIN_SEED_TEXT_LEN - text_len;
        fprintf(stderr, adding_text, (unsigned int)text_len);
        for (;;) {
            unsigned char ch = (rand() % 95) + ' ';
            *(new_txt++) = ch;
            if ((--text_len & 0xF) == 0) {
                if (text_len == 0)
                    break;
                randomize_seed((int)text_len);
            }
        }
        *new_txt = NUL;

        /*
         *  The following code checks for randomly matching
         *  "</text>".  There's one chance in 95 ^ 7 or roughly
         *  1 in 100,000,000,000,000
         *  50% chance of seeing it after a billion tries.
         *  (You get about 60 tries in a 64 byte string.)
         */
        for (;;) {
            new_txt = strstr(res, end_text_mark);
            if (new_txt == NULL)
                break;
            new_txt[1] = '=';
        }
    }

    return res;
}

/**
 * convert version to a number.  Limits version numbers to 4095.4095.4095
 * and ignores anything beyond the third component.
 */
static uint32_t
ver_str_to_number(void)
{
    char const * pz = GNU_PW_MGR_VERSION;
    int32_t   shift = 20;
    uint32_t  res   = 0;

    errno = 0;

    for (;;) {
        char * pn;
        uint32_t v = strtoul(pz, &pn, 10);
        if ((v >= (1<<10)) || (errno != 0))
            die(GNU_PW_MGR_EXIT_CODING_ERROR, bad_vers);
        res += v << shift;
        switch (*pn) {
        case '-': case '\0':
            goto return_res;

        case '.':
            shift -= 10;
            if (shift < 0)
                goto return_res;
            pz = pn + 1;
            continue;

        default:
            die(GNU_PW_MGR_EXIT_CODING_ERROR, bad_vers);
        }
    }

 return_res:
    return res;
}

static inline void
print_new_seed(FILE * fp, char const * cfg_text)
{
    uint32_t     seed_ver = ver_str_to_number();
    char const * seed_txt = get_seed_text();

    if (HAVE_OPT(SECONDARY)) {
        fprintf(fp, cfg_fmt, OPT_ARG(TAG), seed_ver, sec_mark, seed_txt);
        fputs(cfg_text, fp);

    } else {
        char const * rest_of_text = strstr(cfg_text, pw_id_tag);
        fprintf(fp, cfg_fmt, OPT_ARG(TAG), seed_ver, "", seed_txt);

        if (rest_of_text != NULL)
            fwrite(cfg_text, rest_of_text - cfg_text, 1, fp);
        else
            fputs(cfg_text, fp);
    }
}

/**
 * add a new seed to the config file.
 * Both the --tag and --text options were provided.
 */
static void
add_seed(void)
{
    char const * cfg_text = load_config_file();
    FILE * fp;

    {
        char * tag = scribble_get(sizeof (tag_fmt) + strlen(OPT_ARG(TAG)));
        sprintf(tag, tag_fmt, OPT_ARG(TAG));
        if (strstr(cfg_text, tag) != NULL)
            die(GNU_PW_MGR_EXIT_BAD_SEED, dup_tag, OPT_ARG(TAG));
    }

    {
        char const * cfg_file = access_config_file();
        fp = fopen(cfg_file, "w");
        if (fp == NULL)
            fserr(GNU_PW_MGR_EXIT_NO_CONFIG, fopen_z, cfg_file);
    }

    print_new_seed(fp, cfg_text);

    fclose(fp);
}

/**
 * remove a "seed" value indicated by the --tag option.
 */
static void
rm_seed(void)
{
    char const * cfg_data = load_config_file();
    char const * prune    = cfg_data;

    char * tag = scribble_get(tag_fmt_LEN + strlen(OPT_ARG(TAG)) + 1);

    sprintf(tag, tag_fmt, OPT_ARG(TAG));
    tag = strstr(cfg_data, tag);
    if (tag == NULL)
        die(GNU_PW_MGR_EXIT_BAD_SEED, tag_gone_fmt, OPT_ARG(TAG));

    for (;;) {
        char * nxt = strstr(prune, seed_mark);
        if ((nxt > tag) || (nxt == NULL))
            break;
        prune = nxt + 1;
    }

    /*
     * "prune" points to the <seed> mark that encompasses the tag to be removed
     */
    {
        char const * cfg_file = access_config_file();
        FILE * fp = fopen(cfg_file, "w");
        if (fp == NULL)
            fserr(GNU_PW_MGR_EXIT_NO_CONFIG, open_z, cfg_file);
        if (prune > cfg_data)
            fwrite(cfg_data, prune - cfg_data, 1, fp);

        /*
         * If there is another <seed>, print from there.
         * If not, print from the pw_id_tag.
         */
        prune = strstr(tag, seed_mark);
        if (prune != NULL)
            prune++;
        else
            prune = strstr(tag, pw_id_tag);
        if (prune != NULL)
            fputs(prune, fp);
        fclose(fp);
    }
}
