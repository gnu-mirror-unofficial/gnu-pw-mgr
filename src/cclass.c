/*
 *  This file is part of gpw.
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

/**
 * Process the --cclass option from the config file and then re-process
 * the command line versions.
 *
 * @param[in,out] od        the stored option being processed
 * @param[in]     str_list  the list of values from the command line
 */
static void
reprocess_cclass(tOptDesc * od, str_list_t * str_list)
{
    /*
     * The stashed form always erases any pre-existing class bits.
     */
    {
        char * load_line = scribble_get(
            cclass_fmt_LEN + strlen(od->optArg.argString));
        /* "load_line" is size of format plus length of string long */
        sprintf(load_line, cclass_fmt, od->optArg.argString);
        optionLoadLine(&gnu_pw_mgrOptions, load_line);
    }

    /*
     * The validating code (set_pwid_opts) needs to know the current value.
     * Next, reprocess all the command line --cclass options.
     */
    post_cfg_setting = OPT_VALUE_CCLASS;

    {
        str_list_t * sl  = str_list;

        do {
            optionLoadLine(&gnu_pw_mgrOptions, sl->buf);
        } while (sl = sl->next,
                 sl != NULL);
    }

    /*
     * Indicate that the option has been twiddled by the command line.
     * libopts thinks it was last set with "optionLoadLine".
     */
    od->fOptState = (od->fOptState & ~OPTST_SET_MASK) | OPTST_DEFINED;
}

/**
 * replace character classes "pin" and "alnum" with the correct bits.
 * Also implicitly set digit/upper/lower when the @code{two-whatever}
 * character class is specified.
 *
 * @param[in,out] od  the option descriptor for @code{--cclass}.
 */
static void
adjust_pin_n_alnum(tOptDesc * od)
{
    static uintptr_t const alias_mask = CCLASS_PIN | CCLASS_ALNUM;
    uintptr_t bits = OPT_VALUE_CCLASS;

    /*
     * Two of a class always imply one of that class.
     */
    if (bits & CCLASS_TWO_DIGIT)
        bits |= CCLASS_DIGIT;

    if (bits & CCLASS_TWO_UPPER)
        bits |= CCLASS_UPPER;

    if (bits & CCLASS_TWO_LOWER)
        bits |= CCLASS_LOWER;

    /*
     * If alpha characters of either case are required, then plain "alpha"
     * is redundant.  Remove it.
     */
    if ((bits & CCLASS_ALPHA) && (bits & (CCLASS_UPPER | CCLASS_LOWER)))
        bits &= ~CCLASS_ALPHA;

    switch (bits & alias_mask) {
    case 0:
        od->optCookie = (void *)bits;
        return;

    case CCLASS_PIN:
        bits |= CCLASS_NO_ALPHA | CCLASS_NO_SPECIAL;
        break;

    case CCLASS_ALNUM:
        /*
         * If upper or lower is already required, then "alnum: essentially
         * just adds the digit class.
         */
        if (bits & (CCLASS_UPPER | CCLASS_LOWER))
            bits |= CCLASS_DIGIT;
        else
            bits |= CCLASS_ALPHA | CCLASS_DIGIT;
        break;

    case CCLASS_ALNUM | CCLASS_PIN:
        usage_message(alnum_pin_confl);
        /* NOTREACHED */
    }
    bits &= ~alias_mask;
    od->optCookie = (void *)bits;
}

/**
 * Fix up conflicting cclass bits and do not let saved values override
 * the command line.
 *
 * This is called directly from the option handling code.
 * If the option is on the command line, it will be processed first
 * and the next time through, "save_bit_set" will be true.
 *
 * @param[in,out] od  the option descriptor for @code{--cclass}.
 */
static void
fix_cclass_bits(tOptDesc * od)
{
    static bool   save_bits_set   = false;
    static void * save_bits       = NULL;

    adjust_pin_n_alnum(od);

    /*
     * Just save command line option args and do not do anything.
     */
    if (STATE_OPT(CCLASS) == OPTST_DEFINED) {
	save_bits = DESC(CCLASS).optCookie;
	save_bits_set = true;

    } else if (save_bits_set)
	DESC(CCLASS).optCookie = save_bits;
}

/**
 * Validate and (maybe) clean up the cclass bits.  The command line
 * options were already processed before the optionLoadLine call above.
 * During that call, such a condition was detected and the option args
 * were reprocessed in the correct order.  However, while everything is
 * up in the air, consistency cannot be validated.  We can do that now.
 *
 * This routine is either successful or calls \a die().
 */
static void
sanity_check_cclass(void)
{
    do {
        uintptr_t bits = OPT_VALUE_CCLASS;
        static uintptr_t const spec_bits = CCLASS_SPECIAL | CCLASS_NO_SPECIAL;
        if ((bits & spec_bits) != spec_bits)
            break;
        if ((post_cfg_setting & spec_bits) == 0)
            usage_message(inv_cclass);
        bits &= ~(post_cfg_setting & spec_bits);
        DESC(CCLASS).optCookie = (void *)bits;
    } while (false);

    do {
        /*
         * The dual variants of these classes imply these class bits
         */
        static uintptr_t const alpha_bits =
            CCLASS_ALPHA | CCLASS_UPPER | CCLASS_LOWER;

        uintptr_t bits = OPT_VALUE_CCLASS;
        if (((bits & CCLASS_NO_ALPHA) == 0) || ((bits & alpha_bits) == 0))
            break; /* neither prohibited nor required */

        /*
         * we started with alpha chars disabled and added some alpha
         * character types on the command line.  Disable the "no-alpha" flag.
         */
        if (post_cfg_setting & CCLASS_NO_ALPHA)
            bits &= ~CCLASS_NO_ALPHA;

        else {
            /*
             * Turn off all the alpha bits that were on originally.
             * If any are left, then both no-alpha and some alpha
             * class were both added on the command line.  Oops.
             */
            bits &= ~(post_cfg_setting & alpha_bits);
            if ((bits & alpha_bits) != 0)
                usage_message(cclass_conflict);
        }
        DESC(CCLASS).optCookie = (void *)bits;
    } while (false);

    if (OPT_VALUE_LENGTH < MIN_PW_LEN) {
        static uintptr_t const dig_only = CCLASS_NO_ALPHA | CCLASS_NO_SPECIAL;
        if ((OPT_VALUE_CCLASS & dig_only) != dig_only)
            die(GNU_PW_MGR_EXIT_INVALID, pw_too_short,
                (unsigned int)OPT_VALUE_LENGTH);
    }
}
