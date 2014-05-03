# Conkeror password management with gnu-pw-mgr

This library implements functions to insert usernames and/or passwords
from [gnu-pw-mgr](http://www.gnu.org/s/gnu-pw-mgr) in web forms in
[Conkeror](http://www.conkeror.org).

## Executive summary

|Command|Function                  |Description
|-------|--------------------------|---------------------------------------
|`C-x n`|`gnu-pw-mgr-get-user`     |Insert a username in the current field.
|`C-x p`|`gnu-pw-mgr-get-pass`     |Insert a password in the current field.
|`C-x P`|`gnu-pw-mgr-get-user-pass`|Insert a username in the current field, advance to the next field, and then insert the corresponding password.

When you run them, you'll be prompted to enter a password ID.  Of
course, you need to run these commands when the appropriate form field
is focused.  By default the password associated with the most recent
seed is used.  To select a different seed, prefix the command with the
universal argument: e.g., to use the first seed, do `C-u 1 C-x p`.

## Notes

Be warned that Paypal and presumably other sites are doing some
asinine thing with javascript so that the password field only hides
the input when entered via the keyboard; thus, using the above
functions results in your password being visible, which is annoying.
Anyway, a 20-character gnu-pw-mgr-derived password that's only visible
momentarily probably won't be remembered by prying eyes.  But if
anyone finds a way around it, I'd be happy to hear it.

