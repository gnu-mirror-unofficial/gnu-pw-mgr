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
        fprintf(stderr, adding_text, text_len);
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
 * add a new seed to the config file.
 * Both the --tag and --text options were provided.
 */
static void
add_seed(void)
{
    size_t dsz;
    char const * cfg_text = load_config_file();

    {
        char * tag = scribble_get(sizeof (tag_fmt) + strlen(OPT_ARG(TAG)));
        sprintf(tag, tag_fmt, OPT_ARG(TAG));
        if (strstr(cfg_text, tag) != NULL)
            die(GNU_PW_MGR_EXIT_BAD_SEED, dup_tag, OPT_ARG(TAG));
    }

    {
        char const * cfg_file = access_config_file();
        FILE * fp = fopen(cfg_file, "w");
        char * p;
        size_t wlen;
        char const * seed_txt;

        if (fp == NULL)
            fserr(GNU_PW_MGR_EXIT_NO_CONFIG, fopen_z, cfg_file);
        p = strstr(cfg_text, pw_id_tag);
        if (p != NULL)
            wlen = p - cfg_text;
        else
            wlen = strlen(cfg_text);
        if (wlen > 0)
            fwrite(cfg_text, wlen, 1, fp);

        seed_txt = get_seed_text();

        fprintf(fp, cfg_fmt, OPT_ARG(TAG), seed_txt);
        if (p != NULL)
            fputs(p, fp);
        fclose(fp);
    }
}

/**
 * remove a "seed" value indicated by the --tag option.
 */
static void
rm_seed(void)
{
    size_t dsz;
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
