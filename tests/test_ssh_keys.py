"""Resident-key operations and real OpenSSH configuration resolution in temp homes."""
import base64
import importlib.util
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('manage_ssh', ROOT / 'scripts/manage-ssh.py')
ssh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ssh)


def wire(value):
    return struct.pack('>I', len(value)) + value


def public(application='ssh:github.com', byte=1):
    algorithm = b'sk-ssh-ed25519' + b'@' + b'openssh.com'
    blob = wire(algorithm) + wire(bytes([byte]) * 32) + wire(application.encode())
    return algorithm.decode() + ' ' + base64.b64encode(blob).decode() + ' ignored-comment\n'


class SshKeyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.work = self.base / 'work'
        self.work.mkdir(mode=0o700)
        self.target = self.base / 'ssh'
        self.target.mkdir(mode=0o700)
        patcher = patch.object(ssh, 'ssh_directory', return_value=self.target)
        patcher.start()
        self.addCleanup(patcher.stop)

    def resident(self, directory, name, application='ssh:github.com', byte=1, handle=b'H' * 48, cipher=b'none'):
        pub = public(application, byte)
        blob = base64.b64decode(pub.split()[1])
        # As ssh-keygen writes it: check integers, key type, public point,
        # application, flags, key handle (the credential ID), reserved, comment.
        payload = b'\0\0\0\7' * 2 + wire(pub.split()[0].encode()) + wire(bytes([byte]) * 32) + wire(application.encode())
        payload += b'\x01' + wire(handle) + wire(b'') + wire(b'comment')
        envelope = b'openssh-key-v1\0' + wire(cipher) + wire(b'none') + wire(b'') + struct.pack('>I', 1) + wire(blob) + wire(payload)
        (directory / name).write_text(ssh.PRIVATE_BEGIN + '\n' + base64.b64encode(envelope).decode() + '\n-----END-----\n')
        (directory / (name + '.pub')).write_text(pub)

    def configure(self, *names, minutes=0):
        hosts = {'github.com': {'remote': ['git', 'github.com', None], 'names': sorted(names), 'minutes': minutes}}
        ssh.private_directory(self.target / 'omarchy-yubikey')
        (self.target / ssh.MANAGED).write_text(ssh.managed_text(hosts))
        # Absolute path for ssh -G tests; production uses the user's ~/.ssh.
        (self.target / 'config').write_text(ssh.INCLUDE + '\n')
        return hosts

    def test_install_never_overwrites_either_half_and_sets_modes(self):
        self.resident(self.work, 'id_ed25519_sk_rk_a')
        self.resident(self.work, 'id_ed25519_sk_rk_b', byte=2)
        (self.target / 'id_ed25519_sk_rk_b.pub').write_text('existing')
        imported, skipped = ssh.install(self.work, self.target)
        self.assertEqual(imported, ['id_ed25519_sk_rk_a'])
        self.assertEqual(skipped, ['id_ed25519_sk_rk_b'])
        self.assertEqual((self.target / 'id_ed25519_sk_rk_b.pub').read_text(), 'existing')
        for suffix, mode in [('', 0o600), ('.pub', 0o644)]:
            self.assertEqual(stat.S_IMODE((self.target / ('id_ed25519_sk_rk_a' + suffix)).stat().st_mode), mode)

    def test_install_requires_complete_public_pair_and_rolls_back_copy_error(self):
        self.resident(self.work, 'id_ed25519_sk_rk_a')
        (self.work / 'id_ed25519_sk_rk_a.pub').unlink()
        with self.assertRaises(OSError):
            ssh.install(self.work, self.target)
        self.assertEqual(list(self.target.iterdir()), [])
        self.resident(self.work, 'id_ed25519_sk_rk_a')
        original = ssh.copy_exclusive
        def copy(source, target, mode):
            if target.suffix == '.pub':
                raise OSError('synthetic disk full')
            original(source, target, mode)
        with patch.object(ssh, 'copy_exclusive', side_effect=copy), self.assertRaises(OSError):
            ssh.install(self.work, self.target)
        self.assertEqual(list(self.target.iterdir()), [])

    def test_import_is_private_and_failed_partial_download_is_not_installed(self):
        name = 'id_ed25519_sk_rk_a'
        def call(command, cwd, timeout):
            self.assertEqual(command, ['ssh-keygen', '-K'])
            self.assertEqual(stat.S_IMODE(os.stat(cwd).st_mode), 0o700)
            self.resident(Path(cwd), name, 'ssh:')
            return 1
        with patch.dict(os.environ, {'XDG_RUNTIME_DIR': str(self.base)}), patch.object(ssh.subprocess, 'call', side_effect=call), patch('builtins.print'):
            with self.assertRaises(ValueError):
                ssh.do_import()
        self.assertFalse((self.target / name).exists())

    def test_application_is_taken_from_public_blob_not_mutable_comment(self):
        name = 'id_ed25519_sk_rk_a'
        self.resident(self.target, name)
        self.assertEqual(ssh.application(self.target, name), 'ssh:github.com')
        (self.target / (name + '.pub')).write_text(public().replace('ignored-comment', 'ssh:git.evil.example'))
        self.assertEqual(ssh.application(self.target, name), 'ssh:github.com')
        # OpenSSH independently accepts the synthetic public-key wire format.
        subprocess.run(['ssh-keygen', '-l', '-f', str(self.target / (name + '.pub'))],
                       check=True, capture_output=True)

    def test_mismatched_private_file_cannot_be_installed_or_deleted(self):
        name = 'id_ed25519_sk_rk_a'
        self.resident(self.work, name)
        (self.work / (name + '.pub')).write_text(public(byte=2))
        with self.assertRaises(ValueError):
            ssh.install(self.work, self.target)
        self.assertFalse((self.target / name).exists())
        self.resident(self.target, name)
        (self.target / name).write_text('unrelated software secret')
        self.assertEqual(ssh.status()['keys'], [])
        with patch('builtins.input') as ask, self.assertRaises(ValueError):
            ssh.do_remove(ssh.key_reference(self.target, name))
        ask.assert_not_called()

    def test_git_remote_is_allowlisted_and_validates_login_port(self):
        for value, expected in [('ssh:github.com', ('git', 'github.com', None)),
                                ('ssh://forge' + '@' + 'git.example.com:2222', ('forge', 'git.example.com', '2222'))]:
            self.assertEqual(ssh.git_remote(value), expected)
        for value in [None, 'ssh:', 'ssh:example.com', 'ssh:github.com:99999', 'ssh:github.com\nHost *',
                      'ssh:github.com IdentityAgent x']:
            self.assertIsNone(ssh.git_remote(value))

    def test_status_exposes_public_identity_and_no_filename(self):
        name = 'id_ed25519_sk_rk_private-user-id'
        self.resident(self.target, name)
        value = ssh.status()
        self.assertEqual(value['count'], 1)
        key = value['keys'][0]
        self.assertEqual(key['application'], 'ssh:github.com')
        self.assertEqual(key['type'], 'ed25519-sk')
        self.assertRegex(key['fingerprint'], r'^SHA256:[A-Za-z0-9+/]{43}$')
        self.assertRegex(key['id'], r'^[0-9a-f]{64}$')
        self.assertNotIn('private-user-id', repr(value))
        self.assertNotIn('synthetic private handle', repr(value))

    def test_real_openssh_passphrase_detection(self):
        for passphrase in ['', 'synthetic']:
            path = self.base / ('encrypted' if passphrase else 'plain')
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', passphrase, '-f', str(path)], check=True)
            self.assertEqual(ssh.has_passphrase(path), bool(passphrase))

    def test_symlinks_and_nonregular_files_are_not_read_or_replaced(self):
        name = 'id_ed25519_sk_rk_a'
        self.resident(self.target, name)
        (self.target / (name + '.pub')).unlink()
        (self.target / (name + '.pub')).symlink_to(self.base / 'elsewhere')
        self.assertEqual(ssh.status()['keys'], [])
        config = self.target / 'config'
        config.symlink_to(self.base / 'elsewhere')
        with self.assertRaises(OSError):
            ssh.config_text(self.target)
        fifo = self.target / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            ssh.read_file(fifo)

    def test_global_include_is_added_despite_conditional_include_and_preserves_text(self):
        original = 'Host internal.example\n    Include config.d/*.conf\n    User alice\n'
        result = ssh.include_text(original)
        self.assertTrue(result.startswith(ssh.INCLUDE + '\n'))
        self.assertIn(original, result)
        self.assertEqual(ssh.include_text(result), result)
        scoped = 'Host internal.example\n    ' + ssh.INCLUDE + '\n'
        self.assertEqual(ssh.include_text(scoped).count(ssh.INCLUDE), 1)

    def test_zero_reuse_overrides_inherited_multiplexing(self):
        name = 'id_ed25519_sk_rk_a'
        hosts = {'github.com': {'remote': ['git', 'github.com', None], 'names': [name], 'minutes': 0}}
        original = ('Host *\n    User original\n    IdentityAgent /synthetic-agent\n'
                    '    ControlMaster auto\n    ControlPath /synthetic-socket\n    ControlPersist 900\n')
        with patch('builtins.print'):
            ssh.preview(self.target, hosts, ssh.managed_text(hosts), original)
        text = ssh.drop_in_text([name], ('git', 'github.com', None), 0)
        config = self.base / 'resolved'
        config.write_text(text + original)
        options = ssh.ssh_options(config, 'github.com')
        self.assertIn('controlmaster false', options)
        self.assertFalse(any(line.startswith('controlpath ') for line in options))
        self.assertIn('controlpersist no', options)
        self.assertIn('identityagent none', options)
        self.assertIn('user git', options)
        self.assertIn('user original', ssh.ssh_options(config, 'unrelated.example'))

    def test_import_remove_reimport_restores_host_identity_line(self):
        a, b = 'id_ed25519_sk_rk_a', 'id_ed25519_sk_rk_b'
        for i, name in enumerate([a, b], 1):
            self.resident(self.target, name, byte=i)
        self.configure(a, b)
        reference = ssh.key_reference(self.target, a)
        with patch('builtins.input', side_effect=['y', 'y']), patch('builtins.print'):
            ssh.do_remove(reference)
        hosts, _, modified = ssh.load_managed(self.target)
        self.assertFalse(modified)
        self.assertEqual(hosts['github.com']['names'], [b])
        self.resident(self.target, a)
        with patch('builtins.input', side_effect=['y', 'y']), patch('builtins.print'):
            ssh.offer_drop_ins(self.target, [a, b])
        hosts, _, _ = ssh.load_managed(self.target)
        self.assertEqual(hosts['github.com']['names'], [a, b])

    def test_removal_reference_survives_reordering_and_rejects_replaced_public_key(self):
        selected = 'id_ed25519_sk_rk_z'
        self.resident(self.target, selected)
        reference = ssh.key_reference(self.target, selected)
        self.resident(self.target, 'id_ed25519_sk_rk_a', byte=2)
        with patch('builtins.input', return_value='y'), patch('builtins.print'):
            ssh.do_remove(reference)
        self.assertTrue((self.target / 'id_ed25519_sk_rk_a').exists())
        self.resident(self.target, selected, byte=3)
        with patch('builtins.input') as ask, self.assertRaises(ValueError):
            ssh.do_remove(reference)
        ask.assert_not_called()
        self.assertTrue((self.target / selected).exists())

    def test_key_changed_while_confirmation_is_open_is_not_deleted(self):
        name = 'id_ed25519_sk_rk_a'
        self.resident(self.target, name)
        reference = ssh.key_reference(self.target, name)
        def answer(question):
            (self.target / name).write_text('changed')
            return 'y'
        with patch('builtins.input', side_effect=answer), patch('builtins.print'), self.assertRaises(ValueError):
            ssh.do_remove(reference)
        self.assertEqual((self.target / name).read_text(), 'changed')

    def test_manually_edited_managed_file_requires_typed_replacement(self):
        name = 'id_ed25519_sk_rk_a'
        self.resident(self.target, name)
        hosts = self.configure(name)
        path = self.target / ssh.MANAGED
        path.write_text(path.read_text() + '# hand edit\n')
        _, previous, modified = ssh.load_managed(self.target)
        self.assertTrue(modified)
        self.assertTrue(ssh.status()['modified'])
        with patch('builtins.input', return_value='y'), patch('builtins.print'):
            self.assertFalse(ssh.save_hosts(self.target, hosts, previous, modified))
        self.assertIn('# hand edit', path.read_text())
        with patch('builtins.input', return_value='REPLACE'), patch('builtins.print'):
            self.assertTrue(ssh.save_hosts(self.target, hosts, previous, modified))
        self.assertFalse(ssh.load_managed(self.target)[2])

    def test_rejected_ssh_config_never_gets_written(self):
        name = 'id_ed25519_sk_rk_a'
        self.resident(self.target, name)
        (self.target / 'config').write_text('UnknownSyntheticDirective yes\n')
        hosts = {'github.com': {'remote': ['git', 'github.com', None], 'names': [name], 'minutes': 0}}
        with patch('builtins.input') as ask, patch('builtins.print'), self.assertRaises(ValueError):
            ssh.save_hosts(self.target, hosts, '')
        ask.assert_not_called()
        self.assertFalse((self.target / ssh.MANAGED).exists())
        self.assertEqual((self.target / 'config').read_text(), 'UnknownSyntheticDirective yes\n')

    def test_failed_include_write_can_be_finished_by_repeating_import(self):
        name = 'id_ed25519_sk_rk_a'
        self.resident(self.target, name)
        main = 'Host unrelated.example\n    User original\n'
        (self.target / 'config').write_text(main)
        original = ssh.replace_text
        def replace(path, *args, **kwargs):
            if path == self.target / 'config':
                raise OSError('synthetic interrupted write')
            return original(path, *args, **kwargs)
        with patch.object(ssh, 'replace_text', side_effect=replace), \
                patch('builtins.input', side_effect=['y', '0', 'y']), patch('builtins.print'), self.assertRaises(OSError):
            ssh.offer_drop_ins(self.target, [name])
        self.assertTrue((self.target / ssh.MANAGED).exists())
        self.assertEqual((self.target / 'config').read_text(), main)
        self.assertFalse(ssh.status()['keys'][0]['host'])
        with patch('builtins.input', return_value='y'), patch('builtins.print'):
            ssh.offer_drop_ins(self.target, [name])
        self.assertTrue((self.target / 'config').read_text().startswith(ssh.INCLUDE + '\n'))
        self.assertIn(main, (self.target / 'config').read_text())
        self.assertTrue(ssh.status()['keys'][0]['host'])

    def test_fresh_configuration_can_enable_reuse_and_preserves_main_mode(self):
        name = 'id_ed25519_sk_rk_a'
        self.resident(self.target, name)
        config = self.target / 'config'
        config.write_text('Host unrelated.example\n    User original\n')
        config.chmod(0o640)
        with patch('builtins.input', side_effect=['y', '15', 'y']), patch('builtins.print'):
            ssh.offer_drop_ins(self.target, [name])
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o640)
        hosts, text, modified = ssh.load_managed(self.target)
        self.assertEqual(hosts['github.com']['minutes'], 15)
        self.assertIn('ControlPersist 15m', text)
        self.assertFalse(modified)
        before = config.read_bytes(), (self.target / ssh.MANAGED).read_bytes()
        with patch('builtins.input') as ask:
            ssh.offer_drop_ins(self.target, [name])
        ask.assert_not_called()
        self.assertEqual(before, (config.read_bytes(), (self.target / ssh.MANAGED).read_bytes()))

    def test_minutes_default_to_no_reuse_and_are_bounded(self):
        for answer, expected in [('', 0), ('0', 0), ('15', 15), ('1440', 1440)]:
            with patch('builtins.input', return_value=answer):
                self.assertEqual(ssh.ask_minutes(), expected)
        for answer in ['-1', '1441', '0.1', 'x']:
            with patch('builtins.input', return_value=answer), self.assertRaises(ValueError):
                ssh.ask_minutes()

    def test_overlapping_operations_are_rejected(self):
        with ssh.operation_lock(self.target):
            with self.assertRaises(ValueError):
                with ssh.operation_lock(self.target):
                    pass


    def create(self, answers, write=True, result=0, byte=7):
        """Run do_create with scripted answers; ssh-keygen writes a synthetic pair."""
        calls = []
        def call(command, timeout):
            calls.append(command)
            path = Path(command[command.index('-f') + 1])
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            if write:
                app = next(o for o in command if o.startswith('application='))[len('application='):]
                self.resident(path.parent, path.name, app, byte=byte)
            return result
        with patch.object(ssh.subprocess, 'call', side_effect=call), \
                patch('builtins.input', side_effect=answers), patch('builtins.print') as printed, \
                patch.object(ssh, 'offer_drop_ins') as offered, \
                patch.object(ssh.getpass, 'getuser', return_value='alice'), \
                patch.object(ssh.socket, 'gethostname', return_value='laptop'), \
                patch.object(ssh.secrets, 'token_hex', return_value='0123456789abcdef'):
            ssh.do_create()
        return calls, offered, ' '.join(str(c) for c in printed.call_args_list)

    def test_create_builds_the_ssh_keygen_vector_from_the_answers(self):
        # algorithm, application, user ID, PIN, touch, comment, confirm
        calls, offered, output = self.create(['', 'github.com', 'work', '', '', '', 'y'])
        name = 'id_ed25519_sk_rk_github.com_work'
        self.assertEqual(calls[0][:-1], ['ssh-keygen', '-t', 'ed25519-sk', '-O', 'resident',
                                         '-O', 'application=ssh:github.com', '-O', 'user=work',
                                         '-O', 'verify-required', '-C', 'alice@laptop', '-f'])
        self.assertEqual(Path(calls[0][-1]).name, name)
        self.assertTrue((self.target / name).is_file())
        self.assertEqual(stat.S_IMODE((self.target / name).stat().st_mode), 0o600)
        self.assertIn('SHA256:', output)
        self.assertIn('sk-ssh-ed25519', output)
        offered.assert_called_once_with(self.target, [name])
        calls, _, _ = self.create(['ecdsa-sk', '', '-', 'n', 'n', 'test key', 'y'], byte=8)
        self.assertEqual(calls[0][:-1], ['ssh-keygen', '-t', 'ecdsa-sk', '-O', 'resident', '-O', 'application=ssh:',
                                         '-O', 'no-touch-required', '-C', 'test key', '-f'])
        self.assertEqual(Path(calls[0][-1]).name, 'id_ecdsa_sk_rk')

    def test_create_suggests_a_random_user_id(self):
        # Enter keeps the suggestion, so two keys for one application never collide.
        calls, _, output = self.create(['', 'github.com', '', '', '', '', 'y'])
        self.assertIn('user=0123456789abcdef', calls[0])
        self.assertEqual(Path(calls[0][-1]).name, 'id_ed25519_sk_rk_github.com_0123456789abcdef')
        self.assertTrue((self.target / 'id_ed25519_sk_rk_github.com_0123456789abcdef').is_file())
        self.assertNotIn('replaces any other key', output)
        # "-" opts out and warns that it may replace a key without a user ID.
        calls, _, output = self.create(['', 'github.com', '-', '', '', '', 'y'], byte=9)
        self.assertFalse(any(option.startswith('user=') for option in calls[0]))
        self.assertIn('replaces any other key', output)
        self.assertEqual(len(ssh.secrets.token_hex(8)), 16)

    def test_create_names_files_as_ssh_keygen_download_does(self):
        self.assertEqual(ssh.handle_name('ed25519-sk', '', ''), 'id_ed25519_sk_rk')
        self.assertEqual(ssh.handle_name('ed25519-sk', 'github.com', ''), 'id_ed25519_sk_rk_github.com')
        self.assertEqual(ssh.handle_name('ecdsa-sk', '', 'alice'), 'id_ecdsa_sk_rk_alice')
        self.assertEqual(ssh.handle_name('ed25519-sk', 'github.com', 'alice'), 'id_ed25519_sk_rk_github.com_alice')
        for name in ('id_ed25519_sk_rk_github.com_alice', 'id_ecdsa_sk_rk'):
            self.assertTrue(ssh.RESIDENT.fullmatch(name))

    def test_create_rejects_unsafe_application_user_and_comment(self):
        for value in ('git/hub', 'a..b', 'with space', 'line\nbreak', '-flag', 'x' * 200):
            self.assertFalse(ssh.valid_application(value), value)
        for value in ('git/hub', 'a..b', 'with space', 'tab\t', '-flag', 'x' * 70):
            self.assertFalse(ssh.valid_user(value), value)
        self.assertTrue(ssh.valid_application('git' + '@' + 'git.example.com:2222'))
        self.assertTrue(ssh.valid_user('alice.work'))
        for answers in (['rsa'], ['', 'bad/app'], ['', '', 'bad user'], ['', '', '', '', '', 'line\nbreak']):
            with self.assertRaises(ValueError):
                self.create(answers + ['y'] * 6)
        self.assertEqual(list(self.target.iterdir()), [])

    def test_create_checks_names_and_comment_before_the_key_is_made(self):
        # Each would fail only after ssh-keygen, leaving the key on the security
        # key without a copy: an accented comment (.pub read as ASCII) and a
        # handle named like a public half, which import skips.
        for answers in (['', 'github.com', 'work', '', '', 'café'], ['', 'github.com', 'work.pub'],
                        ['', 'x.pub', '-']):
            with self.assertRaises(ValueError):
                calls, _, _ = self.create(answers + ['y'] * 6)
        self.assertEqual(list(self.target.iterdir()), [])
        with patch.object(ssh.subprocess, 'call') as call, patch('builtins.input', side_effect=['', 'github.com', 'work.pub', '', '']):
            with self.assertRaises(ValueError):
                ssh.do_create()
        call.assert_not_called()

    def test_create_cancelled_at_confirmation_runs_nothing(self):
        calls, offered, output = self.create(['', '', '', '', '', '', ''])
        self.assertEqual(calls, [])
        offered.assert_not_called()
        self.assertIn('Cancelled', output)
        self.assertEqual(list(self.target.iterdir()), [])

    def test_create_never_overwrites_and_skips_hosts_for_a_kept_copy(self):
        name = 'id_ed25519_sk_rk_github.com'
        self.resident(self.target, name, byte=9)
        before = (self.target / (name + '.pub')).read_text()
        calls, offered, output = self.create(['', 'github.com', '-', '', '', '', 'y'])
        self.assertEqual(len(calls), 1)
        self.assertEqual((self.target / (name + '.pub')).read_text(), before)
        self.assertIn('security key only', output)
        offered.assert_not_called()

    def test_create_failure_installs_nothing(self):
        with self.assertRaises(ValueError):
            self.create(['', '', '', '', '', '', 'y'], result=1)
        self.assertEqual(list(self.target.iterdir()), [])


    @staticmethod
    def creds(*users):
        lines = []
        for i, (user, cose) in enumerate(users):
            uid = base64.b64encode(user.encode().ljust(32, b'\0') if user else b'\0' * 32).decode()
            lines.append('%02d: %s (null) %s %s uvopt nopay' % (i, chr(ord('D') + i) * 64, uid, cose))
        return '\n'.join(lines) + '\n'

    @staticmethod
    def listing(*handles, user='work'):
        uid = base64.b64encode(user.encode().ljust(32, b'\0')).decode()
        return ''.join('%02d: %s (null) %s eddsa uvopt nopay\n' % (i, base64.b64encode(h).decode(), uid)
                       for i, h in enumerate(handles))

    def test_token_listings_are_parsed_from_the_right(self):
        found = ssh.token_credentials(self.creds(('work', 'eddsa'), ('', 'es256')))
        self.assertEqual([(c['user'], c['type']) for c in found], [('work', 'ed25519-sk'), ('', 'ecdsa-sk')])
        self.assertEqual(found[0]['id'], 'D' * 64)
        spaced = '00: ' + 'E' * 64 + ' Display Name With Spaces ' + base64.b64encode(b'bob').decode() + ' eddsa uvopt nopay\n'
        self.assertEqual(ssh.token_credentials(spaced)[0]['user'], 'bob')
        self.assertEqual(ssh.token_credentials('garbage\n00: not-base64! x y z w v\n'), [])

    def test_key_handle_is_read_from_a_copy_without_passphrase(self):
        self.resident(self.target, 'id_ed25519_sk_rk_x', handle=b'K' * 48)
        self.assertEqual(ssh.key_handle(self.target / 'id_ed25519_sk_rk_x'), b'K' * 48)
        self.resident(self.target, 'id_ed25519_sk_rk_y', cipher=b'aes256-ctr')
        self.assertIsNone(ssh.key_handle(self.target / 'id_ed25519_sk_rk_y'))

    def remove_with(self, name, answers, creds, delete_result=0, token=True, download=None):
        reference = ssh.key_reference(self.target, name)
        real_run = subprocess.run
        def run(command, **options):
            if command == ['fido2-token', '-L']:
                return subprocess.CompletedProcess(command, 0, '/dev/hidraw9: vendor=0x1050 (Yubico)\n')
            if command[1:3] == ['-L', '-k']:
                return subprocess.CompletedProcess(command, 0, creds)
            if command[0] == 'ssh':
                return real_run(command, **options)
            raise AssertionError(command)
        calls = []
        def call(command, timeout, cwd=None):
            calls.append(command)
            if command[:2] == ['ssh-keygen', '-K']:
                for args in download or []:
                    self.resident(Path(cwd), *args)
                return 0
            return delete_result
        with patch.object(ssh.subprocess, 'run', side_effect=run), patch.object(ssh.subprocess, 'call', side_effect=call), \
                patch('builtins.input', side_effect=answers), patch('builtins.print') as printed:
            ssh.do_remove(reference, token=token)
        return calls, ' '.join(str(c) for c in printed.call_args_list)

    def deletes(self, handle):
        return ['fido2-token', '-D', '-i', base64.b64encode(handle).decode(), '/dev/hidraw9']

    def test_remove_keeps_the_key_and_delete_removes_it_from_the_token(self):
        name = 'id_ed25519_sk_rk_github.com_work'
        self.resident(self.target, name)
        # Remove copy: no fido2-token, one y/N, the key stays on the security key.
        calls, output = self.remove_with(name, ['y'], '', token=False)
        self.assertEqual(calls, [])
        self.assertFalse((self.target / name).exists())
        self.assertNotIn('PERMANENT', output)
        # Delete: the credential whose ID is the copy's key handle, after the typed phrase.
        self.resident(self.target, name, handle=b'M' * 48)
        calls, output = self.remove_with(name, ['DELETE ssh:github.com'], self.listing(b'O' * 48, b'M' * 48))
        self.assertEqual(calls, [self.deletes(b'M' * 48)])
        self.assertIn('Matching key', output)
        self.assertIn('PERMANENT', output)
        self.assertFalse((self.target / name).exists())

    def test_delete_never_takes_another_key_with_the_same_application_and_user_id(self):
        # A copy kept after its key was replaced (or made on another security
        # key): same application and user ID on the token, another credential.
        name = 'id_ed25519_sk_rk_github.com_work'
        self.resident(self.target, name, handle=b'O' * 48)
        with self.assertRaises(ValueError) as raised:
            self.remove_with(name, ['DELETE ssh:github.com'], self.listing(b'N' * 48))
        self.assertIn('nothing was deleted', str(raised.exception))
        self.assertTrue((self.target / name).exists())

    def test_delete_finds_the_key_of_a_copy_with_a_passphrase_by_its_public_key(self):
        name = 'id_ed25519_sk_rk_github.com_work'
        self.resident(self.target, name, byte=3, cipher=b'aes256-ctr')
        # The download holds another key too; only the one with the copy's public key counts.
        download = [('id_ed25519_sk_rk_github.com_home', 'ssh:github.com', 4, b'X' * 48),
                    (name, 'ssh:github.com', 3, b'M' * 48)]
        calls, output = self.remove_with(name, ['DELETE ssh:github.com'], self.listing(b'X' * 48, b'M' * 48),
                                         download=download)
        self.assertEqual(calls, [['ssh-keygen', '-K', '-N', ''], self.deletes(b'M' * 48)])
        self.assertIn('has a passphrase', output)
        self.assertFalse((self.target / name).exists())
        # Its key is no longer on the security key: nothing is deleted.
        self.resident(self.target, name, byte=3, cipher=b'aes256-ctr')
        with self.assertRaises(ValueError):
            self.remove_with(name, [], '', download=download[:1])
        self.assertTrue((self.target / name).exists())

    def test_remove_permanent_cancelled_or_failed_keeps_the_copy(self):
        name = 'id_ed25519_sk_rk_github.com_work'
        self.resident(self.target, name, handle=b'M' * 48)
        creds = self.listing(b'M' * 48)
        calls, output = self.remove_with(name, ['delete'], creds)
        self.assertEqual(calls, [])
        self.assertTrue((self.target / name).exists())
        with self.assertRaises(ValueError):
            self.remove_with(name, ['DELETE ssh:github.com'], creds, delete_result=1)
        self.assertTrue((self.target / name).exists())
        calls, output = self.remove_with(name, [''], creds, token=False)
        self.assertEqual(calls, [])
        self.assertTrue((self.target / name).exists())

    def test_delete_asks_about_the_ssh_configuration_before_deleting(self):
        name = 'id_ed25519_sk_rk_github.com_work'
        self.resident(self.target, name, handle=b'M' * 48)
        self.configure(name)
        managed = (self.target / ssh.MANAGED).read_text()
        creds = self.listing(b'M' * 48)
        # Declined: the key stays on the security key, the copy and its host entry too.
        calls, output = self.remove_with(name, ['n'], creds)
        self.assertEqual(calls, [])
        self.assertIn('still on the security key', output)
        self.assertTrue((self.target / name).exists())
        self.assertEqual((self.target / ssh.MANAGED).read_text(), managed)
        # Accepted, then the typed phrase cancels: still nothing written.
        calls, output = self.remove_with(name, ['y', 'no'], creds)
        self.assertEqual(calls, [])
        self.assertEqual((self.target / ssh.MANAGED).read_text(), managed)
        # Accepted and confirmed: deleted, then the entry and the copy go without another question.
        calls, output = self.remove_with(name, ['y', 'DELETE ssh:github.com'], creds)
        self.assertEqual(calls, [self.deletes(b'M' * 48)])
        self.assertNotIn(name, (self.target / ssh.MANAGED).read_text())
        self.assertFalse((self.target / name).exists())
        # A managed file that can't be read stops before anything is deleted.
        self.resident(self.target, name, handle=b'M' * 48)
        (self.target / ssh.MANAGED).write_text('not managed\n')
        with self.assertRaises(ValueError):
            self.remove_with(name, ['DELETE ssh:github.com'], creds)
        self.assertTrue((self.target / name).exists())

if __name__ == '__main__':
    unittest.main()
