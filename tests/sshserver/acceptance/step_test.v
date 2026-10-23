// SPDX-License-Identifier: GPL-2.0-or-later
module main
import os
fn test_guest_stdout_precedes_ssh_warning_without_pipe_backpressure() {
 dir := os.join_path(os.temp_dir(), 'ssh-log-order-${os.getpid()}')
 os.mkdir(dir)!
 defer { os.rmdir_all(dir) or {} }
 hash := 'e35db3f4d24be1f8c653f7980519cf4ec475fc2edddab49b566bffd30276869e'
 text := step(dir, 'warning-before-output', ['sh', '-c',
  'printf "OpenSSH warning\\n" >&2; printf "' + hash + '  /fixture\\n"'], 0, '')!
 assert text.starts_with(hash + '  /fixture\n')
 assert os.read_file(dir + '/warning-before-output.stdout')! == hash + '  /fixture\n'
 assert os.read_file(dir + '/warning-before-output.stderr')! == 'OpenSSH warning\n'
 assert text.ends_with('OpenSSH warning\n')
}
