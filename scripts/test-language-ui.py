#!/usr/bin/env python3
"""Check automatic and live language selection with isolated, synthetic files."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]


def expected(code):
    result = {'code': code}
    for name, source, directory in [('setup', 'Refresh', ROOT / 'i18n/control'),
                                    ('lock', 'Use password', ROOT / 'plugins/yubikey.lock/i18n'),
                                    ('polkit', 'Use password', ROOT / 'plugins/yubikey.polkit/i18n')]:
        strings = {}
        for language in dict.fromkeys(['en', code.split('-')[0], code]):
            path = directory / (language + '.json')
            if path.exists():
                strings.update(json.loads(path.read_text()))
        result[name] = strings[source]
    result['rtl'] = code in ('ar', 'he', 'fa', 'ur')
    return result


def run_case(name, selected, environment, sequence):
    with tempfile.TemporaryDirectory(prefix='yubikey-language-test-') as temporary:
        directory = Path(temporary)
        for local, source in [('Commons', Path('/usr/share/omarchy/shell/Commons')),
                              ('Ui', Path('/usr/share/omarchy/shell/Ui')),
                              ('Setup', ROOT / 'ui'), ('i18n', ROOT / 'i18n'),
                              ('Lock', ROOT / 'plugins/yubikey.lock'),
                              ('Polkit', ROOT / 'plugins/yubikey.polkit')]:
            (directory / local).symlink_to(source)
        language_file = directory / 'config/omarchy/language'
        language_file.parent.mkdir(parents=True)
        if selected is not None:
            language_file.write_text(selected + '\n')
        qml = '''import QtQuick
import Quickshell
import "Setup" as Setup
import "Lock" as Lock
import "Polkit" as Polkit
ShellRoot {
  Setup.Translations { id: setup }
  Lock.Translations { id: lock }
  Polkit.Translations { id: polkit }
  property var expected: EXPECTED
  property int step: 0
  Timer {
    interval: 50; running: true; repeat: true
    onTriggered: {
      var wanted = expected[step]
      if ([setup,lock,polkit].some(function(t) { return t.language !== wanted.code })) return
      if (setup.t("Refresh") !== wanted.setup || lock.t("Use password") !== wanted.lock || polkit.t("Use password") !== wanted.polkit
          || [setup,lock,polkit].some(function(t) { return t.rightToLeft !== wanted.rtl })) {
        console.error("LANGUAGE_TEST_FAILED", wanted.code); Qt.quit(); return
      }
      console.log("LANGUAGE_STEP", step)
      step++
      if (step === expected.length) { running = false; console.log("LANGUAGE_TEST_PASSED"); Qt.quit() }
    }
  }
  Timer { interval: 8000; running: true; onTriggered: { console.error("LANGUAGE_TEST_TIMEOUT", setup.language, lock.language, polkit.language); Qt.quit() } }
}
'''.replace('EXPECTED', json.dumps([expected(code) for code in sequence]))
        (directory / 'shell.qml').write_text(qml)
        env = dict(os.environ)
        for key in ('OMARCHY_YUBIKEY_LANGUAGE', 'OMARCHY_LANGUAGE_FILE', 'LC_ALL', 'LC_MESSAGES', 'LANGUAGE', 'LANG', 'WAYLAND_DISPLAY', 'DISPLAY'):
            env.pop(key, None)
        env.update(XDG_CONFIG_HOME=str(directory / 'config'), QT_QPA_PLATFORM='offscreen', LANG='C.UTF-8')
        env.update(environment)
        # One case also exercises a custom file path, independently of config home.
        if name == 'override-file':
            env['OMARCHY_LANGUAGE_FILE'] = str(language_file)
            env['XDG_CONFIG_HOME'] = str(directory / 'unused')
        output = []
        with subprocess.Popen(['qs', '-p', str(directory / 'shell.qml'), '--no-color'], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as process:
            watchdog = threading.Timer(15, process.kill)
            watchdog.start()
            try:
                for line in process.stdout:
                    output.append(line)
                    for step in range(len(sequence) - 1):
                        if 'LANGUAGE_STEP ' + str(step) in line:
                            # Atomic replacement matches omarchy-language and editor saves.
                            replacement = language_file.with_suffix('.new')
                            replacement.write_text(sequence[step + 1] + '\n')
                            replacement.replace(language_file)
                process.wait(timeout=15)
            finally:
                watchdog.cancel()
                if process.poll() is None:
                    process.kill()
        text = ''.join(output)
        if process.returncode or 'LANGUAGE_TEST_PASSED' not in text or any(
                error in text for error in ('LANGUAGE_TEST_FAILED', 'LANGUAGE_TEST_TIMEOUT', ' ERROR', 'ReferenceError', 'TypeError')):
            raise RuntimeError(name + '\n' + text)
        print('Automatic language UI passed: ' + name)


def main():
    run_case('locale-fallback', None, {'LC_MESSAGES': 'de_AT.UTF-8'}, ['de'])
    run_case('regional-locale', None, {'LANG': 'pt_BR.UTF-8'}, ['pt-BR'])
    run_case('account-and-live-change', 'de', {'LANG': 'en_US.UTF-8'}, ['de', 'pt-BR', 'ar', 'en'])
    run_case('override-file', 'pt-BR', {'LANG': 'de_AT.UTF-8'}, ['pt-BR'])
    run_case('explicit-override', 'de', {'OMARCHY_YUBIKEY_LANGUAGE': 'pt_BR'}, ['pt-BR'])
    run_case('unsafe-code', '../../de', {}, ['en'])


if __name__ == '__main__':
    main()
