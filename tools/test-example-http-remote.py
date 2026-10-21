#!/usr/bin/env python3
"""Round-trip two unchanged ROS example modules through a real loopback server."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import subprocess


def require(value, message):
    if not value:
        raise ValueError(message)


def expected_swap_max():
    value = os.environ.get('UWGIT_EXPECTED_CGROUP_SWAP_MAX', '0')
    require(value in ('max', '0') or (value and value[0] in '123456789' and all(char in '0123456789' for char in value)), 'UWGIT_EXPECTED_CGROUP_SWAP_MAX must be max or canonical nonnegative decimal')
    return value


def pin(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'regular file required: ' + str(path))
    data = path.read_bytes()
    return {'path': str(path), 'byte_len': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('binary', type=Path)
    parser.add_argument('old', type=Path)
    parser.add_argument('new', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    require(platform.system() == 'Linux', 'SSH Linux required')
    membership = Path('/proc/self/cgroup').read_text()
    expected = os.environ['UWGIT_EXPECTED_CGROUP']
    require(membership.splitlines() == ['0::' + expected], 'existing admitted cgroup required')
    require(expected.startswith('/system.slice/docker-') and expected.endswith('.scope'), 'Docker cgroup required')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(boot == os.environ['UWGIT_EXPECTED_BOOT_ID'], 'admitted boot required')
    cg = Path('/sys/fs/cgroup') / expected.lstrip('/')
    swap_max = expected_swap_max()
    expected_limits = {'memory.max': '68719476736', 'memory.swap.max': swap_max, 'cpuset.cpus.effective': '0-31'}
    limits_before = {field: (cg / field).read_text().strip() for field in expected_limits}
    require(limits_before == expected_limits, 'resource limits do not match explicit expectations')
    swap_current_before = (cg / 'memory.swap.current').read_text().strip()
    memory_before = (cg / 'memory.events').read_text()
    require(str(os.getpid()) in (cg / 'cgroup.procs').read_text().splitlines(), 'runner must belong to cgroup')
    for path in (args.binary, args.old, args.new, args.output):
        require(path.is_absolute() and '..' not in path.parts and path.is_relative_to('/tmp'), 'absolute /tmp paths required')
    before = {name: pin(path) for name, path in [('binary', args.binary), ('old', args.old), ('new', args.new)]}
    for path in (args.old, args.new):
        require(path.read_bytes().startswith(b'\0asm\x01\0\0\0'), 'Core module header required')
    require(before['old']['sha256'] != before['new']['sha256'], 'distinct real modules required')
    args.output.mkdir(mode=0o700)
    logs = args.output / 'logs'
    logs.mkdir()
    (args.output / 'admission.json').write_text(json.dumps({'inputs': before, 'cgroup': expected, 'boot_id': boot, 'expected_cgroup_swap_max': swap_max, 'limits_before': limits_before, 'swap_current_before': swap_current_before, 'memory_events': memory_before, 'runner': pin(Path(__file__).resolve())}, indent=2) + '\n')
    repositories = args.output / 'repositories'
    repositories.mkdir()
    upstream, client = repositories / 'project.git', args.output / 'client'
    commands = []
    env = dict(os.environ)
    env.pop('UWGIT_SSH_PROGRAM', None)
    env.pop('UWGIT_REMOTE_PROGRAM', None)
    token = 'uwgit-fixed-loopback-example-test-token'
    token_file = args.output / 'token'
    with token_file.open('xb') as stream:
        os.chmod(token_file, 0o600)
        stream.write(token.encode() + b'\n')
    env['UWGIT_REMOTE_TOKEN'] = token

    def run(*arguments):
        argv = [str(args.binary), *map(str, arguments)]
        index = len(commands)
        stdout, stderr = logs / f'{index}.stdout', logs / f'{index}.stderr'
        with stdout.open('xb') as out, stderr.open('xb') as err:
            result = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=45)
        commands.append({'argv': argv, 'exit_code': result.returncode, 'stdout': pin(stdout), 'stderr': pin(stderr)})
        (args.output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        require(result.returncode == 0, 'command failed: ' + repr(argv))
        return stdout

    server = None
    try:
        run('init', upstream)
        run('commit', upstream, args.old, '-m', 'ROS original before HTTP transfer')
        run('tag', upstream, 'v1')
        with (logs / 'server.stderr').open('xb') as errors:
            server = subprocess.Popen([str(args.binary), 'server', '--root', str(repositories), '--listen', '127.0.0.1:0', '--allow-write', '--token-file', str(token_file)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=errors)
            with selectors.DefaultSelector() as selector:
                selector.register(server.stdout, selectors.EVENT_READ)
                require(selector.select(5), 'server readiness timed out')
                ready = server.stdout.readline()
            (logs / 'server.ready.json').write_bytes(ready)
            address = json.loads(ready)['listen']
            run('clone', f'http://{address}/project.git', client)
            old_export = args.output / 'cloned-old.wasm'
            run('show', client, 'HEAD', '--output', old_export)
            require(old_export.read_bytes() == args.old.read_bytes(), 'clone changed raw module bytes')
            require(all(pin(old_export)[key] == before['old'][key] for key in ('byte_len', 'sha256')), 'clone differs from initial input pin')
            run('commit', client, args.new, '-m', 'ROS original after HTTP transfer')
            run('tag', client, 'v2')
            run('push', client, 'origin', '--tags')
            run('push', client)
            run('push', client, 'origin', 'main:temporary')
            run('push', client, 'origin', '--delete', 'temporary')
            run('fetch', client)
            run('pull', client, 'origin', 'main', '-m', 'verify received ROS history')
            new_export = args.output / 'server-new.wasm'
            run('show', upstream, 'HEAD', '--output', new_export)
            require(new_export.read_bytes() == args.new.read_bytes(), 'push changed raw module bytes')
            require(all(pin(new_export)[key] == before['new'][key] for key in ('byte_len', 'sha256')), 'push differs from initial input pin')
            run('show', client, 'origin/main')
            run('show', upstream, 'refs/tags/v2')
            run('fsck', upstream)
            run('fsck', client)
            run('diff', 'v1', 'v2', '--repo', upstream, '--standard', 'core1', '--format', 'json')
            run('diff', 'v1', 'v2', '--repo', upstream, '--standard', 'core3', '--format', 'json')
        after = {name: pin(path) for name, path in [('binary', args.binary), ('old', args.old), ('new', args.new)]}
        require(before == after, 'binary or reference input changed')
        memory_after = (cg / 'memory.events').read_text()
        counts_before = dict((key, int(value)) for key, value in (line.split() for line in memory_before.splitlines()))
        counts_after = dict((key, int(value)) for key, value in (line.split() for line in memory_after.splitlines()))
        require(counts_after.keys() == counts_before.keys(), 'cgroup event fields changed')
        delta = {key: counts_after[key] - value for key, value in counts_before.items()}
        limits_after = {field: (cg / field).read_text().strip() for field in expected_limits}
        swap_current_after = (cg / 'memory.swap.current').read_text().strip()
        (args.output / 'environment.after.json').write_text(json.dumps({'expected_cgroup_swap_max': swap_max, 'limits_before': limits_before, 'limits_after': limits_after, 'swap_current_before': swap_current_before, 'swap_current_after': swap_current_after, 'memory_events_before': memory_before, 'memory_events_after': memory_after, 'memory_event_deltas': delta}, indent=2) + '\n')
        require(all(value >= 0 for value in delta.values()), 'cgroup event counters decreased')
        require(all(delta[key] == 0 for key in ('oom', 'oom_kill', 'oom_group_kill')), 'cgroup OOM events increased')
        require(limits_after == expected_limits and limits_after == limits_before, 'resource limits changed or differ from explicit expectations')
        require(Path('/proc/self/cgroup').read_text() == membership, 'cgroup changed')
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot, 'boot changed')
        summary = {'passed': True, 'transport': 'real authenticated HTTP loopback server', 'commands': len(commands), 'inputs': before, 'inputs_after': after, 'exports': [pin(old_export), pin(new_export)], 'cgroup': expected, 'boot_id': boot, 'expected_cgroup_swap_max': swap_max, 'limits_before': limits_before, 'limits_after': limits_after, 'swap_current_before': swap_current_before, 'swap_current_after': swap_current_after, 'memory_events_before': memory_before, 'memory_events_after': memory_after, 'memory_event_deltas': delta, 'resource_scope': 'Existing shared cgroup; nonfatal memory.max events may reflect other load. Limits, membership, and OOM deltas are checked.', 'runner': pin(Path(__file__).resolve()), 'fuzzer_run': False}
        (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        print(json.dumps(summary))
    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
        token_file.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
