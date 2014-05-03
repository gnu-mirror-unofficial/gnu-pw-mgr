// gnu-pw-mgr.js --- Retrieve usernames/passwords from gnu-pw-mgr

// Copyright (C) 2014 Brandon Invergo <brandon@invergo.net>

// Author: Brandon Invergo <brandon@invergo.net>

// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 3
// of the License, or (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

// Inspired by:
// http://conkeror.org/Tips#Using_an_external_password_manager

function gnu_pw_mgr_get_pass(elem, str, seed) {
    var out = "";
    var result = yield shell_command(
        "gnu-pw-mgr -H \"" + str + "\"",
        $fds=[{output: async_binary_string_writer("")},
              {input: async_binary_reader(function (s) out += s || "") }]);
    if (seed > 0)
        seed_line = out.split("\n")[seed - 1];
    else
        seed_line = out
    elem.value = seed_line.split(' ').pop();
}

function gnu_pw_mgr_get_user(elem, str) {
    var out = "";
    var result = yield shell_command(
        "gnu-pw-mgr \"" + str + "\"",
        $fds=[{output: async_binary_string_writer("")},
              {input: async_binary_reader(function (s) out += s || "") }]);
    matches = /hint:\s*(\S+)\s*pw:/g.exec(out);
    if (matches)
        elem.value = matches.pop();
}

interactive("gnu-pw-mgr-get-pass",
    "Get a password from gnu-pw-mgr and insert it in the currently focused "+
    "field.  By default, the password associated with the most recent seed "+
    "is given; use the universal argument (C-u) to select a seed by number "+
    "(C-u 1: first, C-u 2: second, etc.)",
    function (I) {
        var n = I.buffer.focused_element;
        yield gnu_pw_mgr_get_pass(
            n,
            (yield I.minibuffer.read($prompt = "Password ID: ")),
            I.prefix_argument);
        browser_element_focus(I.buffer, n);
    });
define_key(content_buffer_normal_keymap, "C-x p", "gnu-pw-mgr-get-pass");

interactive("gnu-pw-mgr-get-user",
    "Get a username from gnu-pw-mgr and insert it in the currently focused "+
    "field.",
    function (I) {
        var n = I.buffer.focused_element;
        yield gnu_pw_mgr_get_user(
            n,
            (yield I.minibuffer.read($prompt = "Password ID: ")));
        browser_element_focus(I.buffer, n);
    });
define_key(content_buffer_normal_keymap, "C-x n", "gnu-pw-mgr-get-user");

interactive("gnu-pw-mgr-get-user-pass",
    "Get a username/password pair from gnu-pw-mgr.  The username is inserted "+
    "in the currently focused field, then focus is switched to the next field "+
    "(which is hopefully the password field), and finally the password is "+
    "inserted into it.  By default, the password associated with the most "+
    "recent seed is given; use the universal argument (C-u) to select a seed "+
    "by number (C-u 1: first, C-u 2: second, etc.)",
    function (I) {
        var n = I.buffer.focused_element;
        passid = yield I.minibuffer.read($prompt = "Password ID: ");
        yield gnu_pw_mgr_get_user(n, passid);
        browser_element_focus(I.buffer, n);
        focus_next(I.buffer, I.p, browser_form_field_xpath_expression,
                   "form field");
        var n = I.buffer.focused_element;
        yield gnu_pw_mgr_get_pass(n, passid, I.prefix_argument);
        browser_element_focus(I.buffer, n);
    });
define_key(content_buffer_normal_keymap, "C-x P", "gnu-pw-mgr-get-user-pass");
