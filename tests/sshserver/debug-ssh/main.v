// SPDX-License-Identifier: GPL-2.0-or-later
// Enable client SSH diagnostics without scp -v adding unsupported remote flags.
module main
import os
fn main() { os.execvp('/usr/bin/ssh', ['-vvv', ...os.args[1..]]) or { eprintln(err); exit(127) } }
