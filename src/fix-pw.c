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

typedef enum { CC_UPPER, CC_LOWER, CC_DIGIT, CC_SPECIAL, CT_CC } ccl_t;

////PULL-HEADERS:

/**
 *  Make sure than any triple characters get fiddled into something with
 *  at most two same characters in a row.
 *
 * @param[in,out] pw  the password string
 * @returns true -> all done, false otherwise
 */
static bool
clean_triplets(char * pw, bool sequence)
{
    bool res = true;
    unsigned char last = *(pw++);
    if (last == NUL)
        die(GNU_PW_MGR_EXIT_CODING_ERROR, inv_pwd);

    for (;; pw++) {
        if (*pw == NUL)
            return res;

        if (*pw != last) {
            last = *pw;
            continue;
        }

        if (*(++pw) == NUL)
            return res;

        if (*pw != last) {
            last = *pw;
            continue;
        }

        /*
         * Three in a row.  Alter the character under the pointer and
         * set "last" to that new character.
         */
        if (isdigit(last)) {
            if (last++ == '9')
                last = '0';

        } else if (isupper(last)) {
            if (last++ == 'Z')
                last = 'A';

        } else if (islower(last)) {
            if (last++ == 'z')
                last = 'a';

        } else
            /*
             * New rule: if sequences are disallowed, then the third
             * repeated special char becomes 'm'. We otherwise could
             * (theoretically) get into an infinite loop.
             */
            last = sequence ? 'm' : OPT_ARG(SPECIALS)[2];

        *pw = last;
        res = false;
    }
}

/**
 *  Make sure that no three characters are sequential.
 *
 * @param[in,out] pw  the password string
 * @returns true -> all done, false otherwise
 */
static bool
clean_sequence(char * pw)
{
    bool res = true;
    unsigned char last[2];

    last[1] = *(pw++);
    if (last[1] == NUL)
        die(GNU_PW_MGR_EXIT_CODING_ERROR, inv_pwd);

    /*
     * Until we hit a NUL byte, check current and previous two chars for
     * a sequence.
     */
    while (last[0] = last[1], last[1] = *(pw++), *pw != NUL) {
        if (*pw != last[1]+1)
            continue; // current does not follow previous

        if (last[1] != last[0]+1)
            continue; // two previous not sequential

        /*
         * We have a triplet sequence. Flip the previous char.
         */
        if (isdigit(last[1])) {
            pw[-1] += (last[1] < '5') ? 5 : -5; // rotate digit 5

        } else if (isupper(last[1])) { // shift upper case by 4
            char ch = last[1] + 4;
            if (ch > 'Z')
                ch = 'A' + (ch - 'Z' - 1);
            pw[-1] = ch;

        } else if (islower(last[1])) { // shift lower case by 4
            char ch = last[1] + 4;
            if (ch > 'z')
                ch = 'a' + (ch - 'z' - 1);
            pw[-1] = ch;

        } else { // select alternate special char
            /*
             * We have three chars in a row with the middle one a special.
             * Pick another of the three special chars.
             */
            pw[-1] = (last[1] != OPT_ARG(SPECIALS)[2])
                ? OPT_ARG(SPECIALS)[2]
                : OPT_ARG(SPECIALS)[1];
        }
        res = false;
    }

    return res;
}

/**
 *  Make sure than any triple characters get fiddled into something with
 *  at most two same characters in a row.
 *
 * @param[in,out] pw  the password string
 */
static bool
clean_no_three(char * pw)
{
    bool triplets = (OPT_VALUE_CCLASS & CCLASS_NO_TRIPLETS) ? true : false;
    bool sequence = (OPT_VALUE_CCLASS & CCLASS_NO_SEQUENCE) ? true : false;
    bool done     = false;
    bool did_work = false;

    assert(triplets || sequence);

    /*
     * Loop until both clean_triplets() and clean_sequence() return true.
     */
    while (! done) {
        bool unchanged = false;
        if (! triplets)
            done = true;
        else
            done = unchanged = clean_triplets(pw, sequence);

        if (sequence) {
            done = clean_sequence(pw);
            unchanged |= done;
        }

        if (UNLIKELY(! unchanged))
            did_work = true;
    }

    return did_work;
}

/**
 * Remove all the alpha characters.  Special chars are either okay or required.
 * If both alphas and specials are disabled, it is a digits-only password.
 *
 * @param[in,out] pw  the password buffer
 */
static void
fix_no_alpha_pw(char * pw)
{
    bool force_spec = (OPT_VALUE_CCLASS & CCLASS_SPECIAL) != 0;
    bool no_spec    = true;

    for (;;) {
        unsigned char ch = *(pw++);
        if (ch == NUL)
            break;

        if (isalpha(ch))
            pw[-1] = '0' + (ch % 10);

        else if (! isdigit(ch))
            no_spec = false;
    }

    if (force_spec && no_spec)
        pw[1] = OPT_ARG(SPECIALS)[2];
}

/**
 * Make all characters lower case.
 *
 * @param[in,out] pw  the password buffer
 */
static void
fix_lower_only_pw(char * pw)
{
    for (;;) {
        unsigned char ch = *(pw++);
        if (ch == NUL)
            break;

        if (islower(ch))
            continue;

        if (isupper(ch)) {
            pw[-1] = 'a' + (ch - 'A');
            continue;
        }

        // we have a digit or '+' or '/' from base64 encoding.
        // these will map thus:  0-9 -> a-j, '+' -> l, '/' -> p
        //
        pw[-1] = 'a' + (ch & 0x0F);
    }
}

/**
 * The character was a special character, but special characters are
 * not allowed.  Therefore, choose a digit, upper or lower case character.
 *
 * @param[in]       ccls  the character classes found to this point
 * @param[in,out]   pch   pointer to the punctuation char to replace
 *
 * @returns the new character class set
 */
static uintptr_t
pick_something(uintptr_t ccls, char * pch, int * cta)
{
    if ((ccls & CCLASS_DIGIT) == 0) {
        *pch = '0' + (*pch & 0x07);
        cta[CC_DIGIT]++;
        return CCLASS_DIGIT;
    }

    if ((ccls & CCLASS_UPPER) == 0) {
        *pch = 'A' + (*pch & 0x0F);
        cta[CC_UPPER]++;
        return CCLASS_ALPHA | CCLASS_UPPER;
    }

    if ((ccls & CCLASS_LOWER) == 0) {
        *pch = 'a' + (*pch & 0x0F);
        cta[CC_LOWER]++;
        return CCLASS_ALPHA | CCLASS_LOWER;
    }

    if ((ccls & CCLASS_TWO_DIGIT) == 0) {
        *pch = '0' + (*pch & 0x07);
        cta[CC_DIGIT]++;
        return CCLASS_TWO_DIGIT;
    }

    if ((ccls & CCLASS_TWO_UPPER) == 0) {
        *pch = 'A' + (*pch & 0x0F);
        cta[CC_UPPER]++;
        return CCLASS_ALPHA | CCLASS_TWO_UPPER;
    }

    /*
     *  Once we have one lower, two digits and two uppers, the rest
     *  will be lower case.  It would be pretty rare :)
     */
    *pch = 'a' + (*pch & 0x0F);
    cta[CC_LOWER]++;
    return CCLASS_ALPHA | CCLASS_TWO_LOWER;
}

/**
 * Count the  character classes in the proposed password.
 *
 * @param[in] pw            the proposed password
 * @param[in] no_spec       true if special characters are disallowed.
 *                          '+' and '/' are mapped to the (possibly default)
 *                          string argument to the \a --cclass option.
 * @param[out] cta          array of character class counts
 *
 * @returns the mask of the classes of characters found in \a pw.
 *
 *  The disallowed character classes are always "found",
 * other than the CCLASS_NO_ALPHA class. That implies all digits and
 * is handled elsewhere.
 */
static uintptr_t
count_pw_class(char * pw, bool no_spec, int * cta)
{
    static uintptr_t const never = CCLASS_NO_SPECIAL | CCLASS_NO_THREE;

    uintptr_t res = OPT_VALUE_CCLASS & never;
    char *   scan = pw;

    memset(cta, NUL, CT_CC * sizeof(*cta));

    for (;;) {
        unsigned char ch = (unsigned char)*(scan++);
        if (ch == NUL)
            return res;

        if (isdigit(ch)) {
            cta[CC_DIGIT]++;
            if ((res & CCLASS_DIGIT) != 0)
                res |= CCLASS_TWO_DIGIT;
            else
                res |= CCLASS_DIGIT;

        } else if (islower(ch)) {
            cta[CC_LOWER]++;

            if ((res & CCLASS_LOWER) != 0)
                res |= CCLASS_TWO_LOWER;
            else
                res |= CCLASS_ALPHA | CCLASS_LOWER;

        } else if (isupper(ch)) {
            cta[CC_UPPER]++;

            if ((res & CCLASS_UPPER) != 0)
                res |= CCLASS_TWO_UPPER;
            else
                res |= CCLASS_ALPHA | CCLASS_UPPER;

        } else if (! no_spec) {
            cta[CC_SPECIAL]++;
            if ((res & CCLASS_SPECIAL) != 0)
                res |= CCLASS_TWO_SPECIAL;
            else
                res |= CCLASS_SPECIAL;

            if (HAVE_OPT(SPECIALS)) {
                switch (ch) {
                case '/': scan[-1] = OPT_ARG(SPECIALS)[0]; break;
                case '+': scan[-1] = OPT_ARG(SPECIALS)[1]; break;
                }
            }

        /*
         *  Found a special character, but no specials are allowed.
         */
        } else
            res |= pick_something(res, scan-1, cta);
    }
}

static char *
find_upper(char * pw)
{
    pw += strlen(pw);
    for (;;) {
        if (isupper((unsigned int)*--pw))
            return pw;
    }
}

static char *
find_lower(char * pw)
{
    pw += strlen(pw);
    for (;;) {
        if (islower((unsigned int)*--pw))
            return pw;
    }
}

static char *
find_digit(char * pw)
{
    pw += strlen(pw);
    for (;;) {
        if (isdigit((unsigned int)*--pw))
            return pw;
    }
}

static char *
find_special(char * pw)
{
    pw += strlen(pw);
    for (;;) {
        if (ispunct((unsigned int)*--pw))
            return pw;
    }
}

static void
add_upper(char * pw, int * cta)
{
    if (cta[CC_LOWER] > 2) {
        pw = find_lower(pw);
        cta[CC_LOWER]--;

    } else if (cta[CC_DIGIT] > 2) {
        pw = find_digit(pw);
        cta[CC_DIGIT]--;

    } else {
        pw = find_special(pw);
        cta[CC_SPECIAL]--;
    }

    *pw = 'A' + (*pw & 0x0F);
    cta[CC_UPPER]++;
}

static void
add_lower(char * pw, int * cta)
{
    if (cta[CC_UPPER] > 2) {
        pw = find_upper(pw);
        cta[CC_UPPER]--;

    } else if (cta[CC_DIGIT] > 2) {
        pw = find_digit(pw);
        cta[CC_DIGIT]--;

    } else {
        pw = find_special(pw);
        cta[CC_SPECIAL]--;
    }

    *pw = 'a' + (*pw & 0x0F);
    cta[CC_LOWER]++;
}

static void
add_digit(char * pw, int * cta)
{
    if (cta[CC_UPPER] > 2) {
        pw = find_upper(pw);
        cta[CC_UPPER]--;

    } else if (cta[CC_LOWER] > 2) {
        pw = find_lower(pw);
        cta[CC_LOWER]--;

    } else {
        pw = find_special(pw);
        cta[CC_SPECIAL]--;
    }

    *pw = '0' + (*pw & 0x07);
    cta[CC_DIGIT]++;
}

static void
add_special(char * pw, int * cta)
{
    if (cta[CC_DIGIT] > 2) {
        pw = find_digit(pw);
        cta[CC_DIGIT]--;

    } else if (cta[CC_LOWER] > 2) {
        pw = find_lower(pw);
        cta[CC_LOWER]--;

    } else {
        pw = find_upper(pw);
        cta[CC_UPPER]--;
    }

    {
        int ix = cta[CC_SPECIAL]++;
        if (ix > 2)
            ix = 2;
        *pw = OPT_ARG(SPECIALS)[ix];
    }
}

/**
 * fiddle the password to comply with requirements.  Special characters may be
 * required or prohibited.  Both upper and lower case letters may be required.
 * The password may be forced to be all digits.  The @code{--class} option
 * should be specific to each password id. If "clean_no_three()" makes changes,
 * then we need to sanity check the result. It's possible a minimum count of
 * a character class get violated.
 *
 * Except for when special characters are required, with reasonable length
 * passwords, it is unusual for this fixup function to do anything.
 *
 * @param[in,out] pw  the password buffer
 */
static void
fix_std_pw(char * pw)
{
    int cta[4];
    uintptr_t need;

    for (;;) {
        {
            bool no_spec = (OPT_VALUE_CCLASS & CCLASS_NO_SPECIAL)  ? true : false;
            need = count_pw_class(pw, no_spec, cta);
            need = (need & OPT_VALUE_CCLASS) ^ OPT_VALUE_CCLASS;
        }

        /*
         * IF there are any needs, it is probably because special chars are
         * required, but none got into the result.
         */
        if (UNLIKELY(need != 0)) {

            if (ISLIKELY((need & CCLASS_SPECIAL) != 0))
                add_special(pw, cta);

            if (UNLIKELY((need & CCLASS_TWO_SPECIAL) != 0))
                add_special(pw, cta); // unusual requirement

            /*
             * "need" are the bits in OPT_VALUE_CLASS not found by count_pw_class
             *
             * requiring "alpha" is always one-only and can never be in
             * conjunction with upper or lower.
             */
            if ((need & CCLASS_ALPHA) != 0)
                add_upper(pw, cta);

            else {
                if ((need & CCLASS_UPPER) != 0)
                    add_upper(pw, cta);

                if (UNLIKELY((need & CCLASS_TWO_UPPER) != 0))
                    add_upper(pw, cta);

                if ((need & CCLASS_LOWER) != 0)
                    add_lower(pw, cta);

                if (UNLIKELY((need & CCLASS_TWO_LOWER) != 0))
                    add_lower(pw, cta);
            }

            if ((need & CCLASS_DIGIT) != 0)
                add_digit(pw, cta);

            if (UNLIKELY((need & CCLASS_TWO_DIGIT) != 0))
                add_digit(pw, cta);
        }

        if (ISLIKELY((OPT_VALUE_CCLASS & CCLASS_NO_THREE) == 0))
            return;

        if (ISLIKELY(! clean_no_three(pw)))
            return;
        /*
         * "clean_no_three()" did some cleaning, so recompute
         * the satisfied classes and try again.
         */
    }
}

/**
 * Fill the buffer with digits.  By default, convert the sha256 sum to
 * four (or 8) decimal integer strings, skip the first 3 digits and
 * use the remainder.  The first digit has 33% chance of being "1" and
 * the second digit is somewhat non-uniform in its distribution.
 * The third should be random enough, but we have digits to burn, so...
 *
 * @param[out] pw    the password buffer
 * @param[in]  sums  the sha256 sums as seen as pointer sized integers
 */
static void
fix_digit_pw(char * pw, uintptr_t * sums)
{
    /*
     * log10((2 ^^ 64) - 1) is 20, plus a NUL and round up to multiple of
     * sizeof(int) yields 24.
     */
    char bf[24];
    size_t need_ln;
    size_t str_ln;
    int    lp_lim = 256 / (NBBY * sizeof(*sums));

    for (need_ln = OPT_VALUE_LENGTH; (lp_lim-- > 0) && (need_ln > 0); ) {
        sprintf(bf, "%lu", *(sums++));
        str_ln = strlen(bf);
        if (str_ln < 5)
            continue;
        str_ln -= 4;
        if (str_ln > need_ln) {
            memcpy(pw, bf + 4 + str_ln - need_ln, need_ln + 1);
            return;
        }
        memcpy(pw, bf + 4, str_ln);
        pw      += str_ln;
        need_ln -= str_ln;
    }

    while (need_ln > 0) {
        size_t cln = (need_ln > 10) ? 10 : need_ln;
        need_ln -= cln;
        memcpy(pw, digits_z, cln);
        pw += cln;
    }
    *pw = NUL;
}
