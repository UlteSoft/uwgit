#!/usr/bin/env python3
"""Exercise a multi-Wasm tree through the admitted temporary OpenSSH service.

The parent test-ssh-server-remote.sh owns the loopback daemon, temporary keys,
pinned known_hosts and cleanup. This optional child uses only that admitted SSH
transport and writes a separate command log, input pins and summary under /tmp.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess

A = 'modules/client.wasm'
B = 'nested/services/server.wasm'
C = 'added/observer.wasm'
HEADER = b'\0asm\x01\0\0\0'


def require(value, message):
    if not value:
        raise ValueError(message)


def expected_swap_max():
    value = os.environ.get('UWGIT_EXPECTED_CGROUP_SWAP_MAX', '0')
    require(value in ('max', '0') or (value and value[0] in '123456789' and all(char in '0123456789' for char in value)), 'UWGIT_EXPECTED_CGROUP_SWAP_MAX must be max or canonical nonnegative decimal')
    return value


def regular(path):
    path = Path(path)
    require(stat.S_ISREG(path.lstat().st_mode), 'regular non-symlink file required: ' + str(path))
    return path.read_bytes()


def pin(path):
    data = regular(path)
    return {'path': str(path), 'byte_len': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def counters(text):
    return {key: int(value) for key, value in (line.split() for line in text.splitlines())}


def immutable_id(value):
    require(isinstance(value, str) and len(value) == 64 and all(char in '0123456789abcdef' for char in value), 'complete immutable commit ID required')
    return value


def replay_audit(audit, old, new):
    require(audit['old']['byte_len'] == len(old) and audit['new']['byte_len'] == len(new), 'resolution delta audit length mismatch')
    old_cursor = new_cursor = 0
    rebuilt = bytearray()
    for edit in audit['edits']:
        start, end = edit['old_span']['start'], edit['old_span']['end']
        new_start, new_end = edit['new_span']['start'], edit['new_span']['end']
        require(all(type(value) is int for value in [start, end, new_start, new_end]), 'noninteger resolution edit boundary')
        require(old_cursor <= start <= end <= len(old) and new_cursor <= new_start <= new_end <= len(new), 'resolution edit spans overlap or escape original modules')
        require(edit['old_hex'] == old[start:end].hex() and edit['new_hex'] == new[new_start:new_end].hex(), 'resolution edit omitted raw byte evidence')
        require(old[old_cursor:start] == new[new_cursor:new_start], 'resolution audit omitted an intervening change')
        rebuilt.extend(old[old_cursor:start])
        rebuilt.extend(bytes.fromhex(edit['new_hex']))
        old_cursor, new_cursor = end, new_end
    require(old[old_cursor:] == new[new_cursor:], 'resolution audit omitted a trailing change')
    rebuilt.extend(old[old_cursor:])
    require(bytes(rebuilt) == new, 'resolution audit edits do not reconstruct the exact supplied module')


def resolution_evidence(report, base, ours, theirs, resolved):
    require(report['status'] == 'merged_resolved', 'manual tree resolution did not publish a reviewed merge')
    require(report['resolution_source'] == 'index' and report['index_updated'] is False and report['worktree_updated'] is False, 'manual resolution must preserve the supplied index and dirty worktree')
    evidence = report['tree_manual_resolution']
    require(evidence['supplied_complete_tree'] is True and evidence['provenance'] and evidence['legacy_path'] is None, 'manual tree resolution provenance is missing or guessed')
    sides = {'base': base, 'ours': ours, 'theirs': theirs, 'resolved': resolved}
    expected_paths = set().union(*(files.keys() for files in sides.values()))
    rows = evidence['files']
    require(len(rows) == len(expected_paths) and {row['path'] for row in rows} == expected_paths, 'manual evidence omits or duplicates a tree path')
    replayed = []
    for row in rows:
        name = row['path']
        for side, files in sides.items():
            data = files.get(name)
            witness = row[side]
            if data is None:
                require(witness is None, 'absent path was replaced with an invented empty module')
            else:
                require(witness['byte_len'] == len(data) and witness['sha256'] == hashlib.sha256(data).hexdigest() and witness['hex'] == data.hex(), 'manual resolution witness differs from original ' + side + ' bytes: ' + name)
                require(witness['audit']['byte_len'] == len(data), 'manual witness audit uses different bytes')
        for side, files in [('from_ours', ours), ('from_theirs', theirs)]:
            old, new = files.get(name), resolved.get(name)
            status = 'absent' if old is None and new is None else 'added' if old is None else 'deleted' if new is None else 'unchanged' if old == new else 'modified'
            require(row[side]['status'] == status, 'manual resolution delta has the wrong presence/change status')
            if status == 'modified':
                replay_audit(row[side]['audit'], old, new)
                replayed.append({'path': name, 'side': side})
            else:
                require(row[side].get('audit') is None, 'one-sided or unchanged resolution delta invents a paired module audit')
    return {'union_paths': sorted(expected_paths), 'replayed_modified_deltas': replayed}


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--authority', required=True)
    parser.add_argument('--old-a', required=True, type=Path)
    parser.add_argument('--old-b', required=True, type=Path)
    parser.add_argument('--new-a', required=True, type=Path)
    parser.add_argument('--new-b', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    require(platform.system() == 'Linux', 'admitted SSH Linux required')
    expected = os.environ['UWGIT_EXPECTED_CGROUP']
    membership = Path('/proc/self/cgroup').read_text()
    require(membership.splitlines() == ['0::' + expected], 'existing admitted cgroup required')
    require(expected.startswith('/system.slice/docker-') and expected.endswith('.scope'), 'Docker cgroup required')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(boot == os.environ['UWGIT_EXPECTED_BOOT_ID'], 'admitted boot required')
    cg = Path('/sys/fs/cgroup') / expected.lstrip('/')
    swap_max = expected_swap_max()
    limits = {field: (cg / field).read_text().strip() for field in ['memory.max', 'memory.swap.max', 'cpuset.cpus.effective']}
    require(limits == {'memory.max': '68719476736', 'memory.swap.max': swap_max, 'cpuset.cpus.effective': '0-31'}, 'admitted resource limits required')
    swap_current_before = (cg / 'memory.swap.current').read_text().strip()
    require(str(os.getpid()) in (cg / 'cgroup.procs').read_text().splitlines(), 'runner must belong to admitted cgroup')
    events_before = counters((cg / 'memory.events').read_text())
    sources = {'old_a': args.old_a, 'old_b': args.old_b, 'new_a': args.new_a, 'new_b': args.new_b}
    for path in [args.binary, args.root, args.output, *sources.values()]:
        require(path.is_absolute() and '..' not in path.parts and path.is_relative_to('/tmp'), 'absolute /tmp paths required')
    require(args.root.is_dir() and not args.root.is_symlink(), 'existing server root required')
    require(args.authority and '/' not in args.authority and not any(ord(char) <= 32 for char in args.authority), 'SSH authority only')
    require(os.environ.get('UWGIT_SSH_PROGRAM'), 'parent temporary SSH program required')
    require(os.environ.get('UWGIT_REMOTE_PROGRAM') == str(args.binary), 'remote executable must be the pinned binary')
    binary_before = pin(args.binary)
    script_before = pin(Path(__file__).absolute())
    inputs_before = {name: pin(path) for name, path in sources.items()}
    require(inputs_before['old_a']['sha256'] != inputs_before['new_a']['sha256'], 'the updated module must change bytes')
    args.output.mkdir(mode=0o700)
    logs = args.output / 'logs'
    logs.mkdir()
    copies = args.output / 'inputs'
    copies.mkdir()
    input_data = {}
    input_pins = {}
    for name, source in sources.items():
        data = regular(source)
        require(data.startswith(HEADER), 'Core Wasm module header required')
        require(hashlib.sha256(data).hexdigest() == inputs_before[name]['sha256'], 'input changed before copying')
        destination = copies / (name + '.wasm')
        with destination.open('xb') as stream:
            stream.write(data)
        require(pin(source) == inputs_before[name], 'input changed while copying')
        require(regular(destination) == data, 'input copy changed bytes')
        input_data[name] = data
        input_pins[name] = pin(destination)
    (args.output / 'input-pins.json').write_text(json.dumps({'before': inputs_before, 'copies': input_pins}, indent=2) + '\n')
    env = dict(os.environ)
    env.pop('UWGIT_REMOTE_TOKEN', None)
    commands = []

    def run(*arguments, expected_exit=0):
        require(type(expected_exit) is int and expected_exit in (0, 2), 'only success or an explicitly expected content conflict is allowed')
        argv = [str(args.binary), *map(str, arguments)]
        index = len(commands)
        stdout, stderr = logs / f'{index}.stdout', logs / f'{index}.stderr'
        timed_out = False
        with stdout.open('xb') as out, stderr.open('xb') as err:
            try:
                result = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=45)
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = None
                timed_out = True
        commands.append({'argv': argv, 'expected_exit': expected_exit, 'exit_code': code, 'timed_out': timed_out, 'stdout': pin(stdout), 'stderr': pin(stderr)})
        (args.output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        require(not timed_out and code == expected_exit, 'command returned ' + repr(code) + ', expected ' + str(expected_exit) + ': ' + repr(argv))
        return stdout

    def identifier(repository, revision='HEAD'):
        return run('rev-parse', repository, revision).read_text().strip()

    def export(repository, revision, file, name, expected):
        destination = args.output / name
        run('show', repository, revision, '--file', file, '--output', destination)
        require(regular(destination) == expected, 'export changed bytes for ' + file)
        return pin(destination)

    def write(repository, file, data):
        destination = repository / file
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)

    def local_refs(repository):
        metadata = repository / '.uwgit'
        paths = [metadata / 'HEAD']
        for directory in ['refs', 'tags']:
            if (metadata / directory).exists():
                paths.extend(sorted((metadata / directory).iterdir()))
        return {str(path.relative_to(metadata)): pin(path) for path in paths}

    def worktree_snapshot(repository):
        snapshot = {}
        for root, directories, files in os.walk(repository, followlinks=False):
            root = Path(root)
            if root == repository:
                directories.remove('.uwgit')
            for name in directories:
                directory = root / name
                require(stat.S_ISDIR(directory.lstat().st_mode), 'unexpected worktree symlink or non-directory')
                snapshot[str(directory.relative_to(repository))] = {'kind': 'directory'}
            for name in files:
                file = root / name
                snapshot[str(file.relative_to(repository))] = {'kind': 'file', **pin(file)}
        return snapshot

    def staged_commit(repository, message):
        fields = run('commit', repository, '-m', message).read_text().split()
        require(len(fields) == 2 and fields[0] == 'main', 'unexpected staged commit result')
        return immutable_id(fields[1])

    def shown_commit(repository, revision, expected_id, parents):
        report_path = run('show', repository, revision)
        report = json.loads(report_path.read_bytes())
        require(report['id'] == expected_id and report['parents'] == parents and report['format'] == 2, 'transferred tree commit or exact ordered parents changed')
        return pin(report_path)

    work, client = args.output / 'work', args.output / 'client'
    upstream = args.root / 'tree-project'
    url = f'ssh://{args.authority}{upstream}'
    run('init', work)
    write(work, A, input_data['old_a'])
    write(work, B, input_data['old_b'])
    run('add', work, A, B)
    run('commit', work, '-m', 'two original ROS modules')
    run('tag', work, 'base')
    run('branch', work, 'feature')
    initial = identifier(work)
    run('clone', work, upstream)
    run('remote', work, 'add', 'origin', url)
    run('clone', url, client)
    require(identifier(client) == initial, 'SSH clone changed tree commit')
    exports = [export(client, 'HEAD', A, 'cloned-a.wasm', input_data['old_a']), export(client, 'HEAD', B, 'cloned-b.wasm', input_data['old_b'])]
    run('restore', client, '--source', 'HEAD', '--staged', '--worktree')
    require(regular(client / A) == input_data['old_a'] and regular(client / B) == input_data['old_b'], 'restored tree bytes differ')
    write(client, A, input_data['new_a'])
    write(client, C, input_data['new_b'])
    run('add', client, A, C)
    run('rm', client, '--cached', B)
    run('commit', client, '-m', 'change add and remove ROS module paths')
    changed = identifier(client)
    run('tag', client, 'release')
    run('push', client)
    run('push', client, 'origin', '--tags')
    run('push', client, 'origin', 'HEAD:temporary')
    run('push', client, 'origin', '--delete', 'temporary')
    run('push', client, 'origin', '--delete', 'refs/tags/release')
    require(identifier(upstream) == changed, 'SSH push changed tree commit')
    exports.extend([export(upstream, 'HEAD', A, 'pushed-a.wasm', input_data['new_a']), export(upstream, 'HEAD', C, 'pushed-c.wasm', input_data['new_b'])])
    refs_before = local_refs(work)
    index_before = pin(work / '.uwgit/index')
    run('fetch', work)
    require(local_refs(work) == refs_before and pin(work / '.uwgit/index') == index_before, 'fetch changed local refs or index')
    require(regular(work / A) == input_data['old_a'] and regular(work / B) == input_data['old_b'], 'fetch changed working files')
    require(identifier(work, 'origin/main') == changed, 'remote tracking lacks changed tree')
    run('pull', work, 'origin', 'main', '-m', 'integrate received ROS tree')
    require(identifier(work) == changed, 'pull did not integrate exact tree commit')
    require(regular(work / A) == input_data['new_a'] and regular(work / C) == input_data['new_b'], 'pull changed file bytes')
    require(not (work / B).exists(), 'pull did not remove deleted path')
    tree_diff_path = run('diff', initial, changed, '--repo', upstream, '--format', 'json')
    tree_diff = json.loads(tree_diff_path.read_bytes())
    require(tree_diff['kind'] == 'tree_diff' and tree_diff['binary_changed'], 'tree diff did not find original module changes')
    require({item['path']: item['status'] for item in tree_diff['files']} == {A: 'modified', B: 'deleted', C: 'added'}, 'tree diff did not identify exact path changes')
    single_diff_path = run('diff', initial, changed, '--repo', upstream, '--file', A, '--format', 'json')
    single_diff = json.loads(single_diff_path.read_bytes())
    require(single_diff['binary_changed'] and single_diff['audit']['edits'], 'selected module diff omitted edits')
    run('rm', client, '--cached', A, C)
    run('commit', client, '-m', 'empty Core Wasm tree')
    empty_tip = identifier(client)
    run('push', client)
    empty = args.output / 'empty-clone'
    run('clone', url, empty)
    require(identifier(empty) == empty_tip, 'empty-tree clone changed commit')
    inspection = json.loads(run('inspect', 'HEAD', '--repo', empty, '--json').read_bytes())
    require(inspection['kind'] == 'tree_inspect' and inspection['file_count'] == 0 and inspection['files'] == [], 'empty tree was not preserved')
    for repository in [upstream, work, client, empty]:
        run('fsck', repository)
    original_commands = len(commands)
    require(original_commands == 43 and all(row['expected_exit'] == 0 for row in commands), 'original 43-command tree workflow changed')

    # This second set of repositories shares only the admitted SSH daemon and
    # original pinned module bytes with the preceding, unchanged workflow.
    resolution_root = args.output / 'resolution'
    resolution_root.mkdir(mode=0o700)
    resolution_work = resolution_root / 'work'
    left, right = resolution_root / 'left', resolution_root / 'right'
    resolution_upstream = args.root / 'resolution-project.git'
    resolution_url = f'ssh://{args.authority}{resolution_upstream}'
    child_path = A + '/nested.wasm'
    conflict_path = 'resolution/conflict.wasm'
    base_files = {A: input_data['old_a'], B: input_data['old_b']}
    run('init', resolution_work)
    for file, data in base_files.items():
        write(resolution_work, file, data)
    run('add', resolution_work, A, B)
    resolution_base = staged_commit(resolution_work, 'two unchanged ROS modules for reviewed merges')
    run('clone', resolution_work, resolution_upstream)
    for repository in [left, right]:
        run('clone', resolution_url, repository)
        run('restore', repository, '--source', 'HEAD', '--staged', '--worktree')
        require(all(regular(repository / name) == data for name, data in base_files.items()), 'resolution clone or restoration changed a base module')
    left_files = {**base_files, conflict_path: input_data['new_a']}
    right_files = {**base_files, conflict_path: input_data['old_a']}
    write(left, conflict_path, input_data['new_a'])
    run('add', left, conflict_path)
    left_tip = staged_commit(left, 'left adds an original ROS module at the conflict path')
    write(right, conflict_path, input_data['old_a'])
    run('add', right, conflict_path)
    right_tip = staged_commit(right, 'right adds different original ROS bytes at the same path')
    run('push', right)
    left_refs = local_refs(left)
    left_index = pin(left / '.uwgit/index')
    left_worktree = worktree_snapshot(left)
    run('fetch', left)
    require(local_refs(left) == left_refs and pin(left / '.uwgit/index') == left_index and worktree_snapshot(left) == left_worktree, 'resolution fetch changed local refs, index or worktree')
    conflict_command = len(commands)
    conflict_report_path = run('pull', left, 'origin', 'main', '-m', 'report add/add conflict without publishing', expected_exit=2)
    conflict_report = json.loads(conflict_report_path.read_bytes())
    require(conflict_report['status'] == 'conflict' and conflict_report['old_head'] == left_tip and conflict_report['target'] == right_tip and conflict_report['base'] == resolution_base, 'expected pull conflict does not bind both reviewed tips')
    require(any(row['path'] == conflict_path and row['status'] == 'conflict' for row in conflict_report['file_reports']), 'add/add conflict path missing from report')
    require(local_refs(left) == left_refs and pin(left / '.uwgit/index') == left_index and worktree_snapshot(left) == left_worktree, 'conflicted pull changed HEAD, index or worktree')

    run('mv', left, A, child_path)
    write(left, B, input_data['new_b'])
    run('add', left, B)
    resolved_files = {child_path: input_data['old_a'], B: input_data['new_b'], conflict_path: input_data['new_a']}
    dirty_bytes = input_data['old_a'] if input_data['old_a'] != input_data['new_b'] else input_data['new_a']
    write(left, B, dirty_bytes)
    supplied_index = pin(left / '.uwgit/index')
    supplied_worktree = worktree_snapshot(left)
    manual_report_path = run('merge', left, right_tip, '-m', 'review exact original-module index with file to directory conversion', '--resolved-index', '--expect-head', left_tip)
    manual_report = json.loads(manual_report_path.read_bytes())
    first_evidence = resolution_evidence(manual_report, base_files, left_files, right_files, resolved_files)
    require(first_evidence['replayed_modified_deltas'], 'manual merge did not expose the changed original ROS module delta')
    merged_tip = immutable_id(manual_report['commit'])
    require(manual_report['old_head'] == left_tip and manual_report['target'] == right_tip and manual_report['base'] == resolution_base, 'manual resolution changed the reviewed tips or base')
    require(pin(left / '.uwgit/index') == supplied_index and worktree_snapshot(left) == supplied_worktree, 'manual tree merge changed the supplied index or dirty worktree')
    manual_commit_pin = shown_commit(left, 'HEAD', merged_tip, [left_tip, right_tip])
    run('push', left)
    run('pull', right, 'origin', 'main', '-m', 'receive reviewed file to directory conversion')
    received_merge_pin = shown_commit(right, 'HEAD', merged_tip, [left_tip, right_tip])
    require((right / A).is_dir() and all(regular(right / name) == data for name, data in resolved_files.items()), 'SSH pull did not apply exact file-to-directory tree bytes')
    resolution_exports = [
        export(right, 'HEAD', child_path, 'resolution/received-child.wasm', input_data['old_a']),
        export(right, 'HEAD', B, 'resolution/received-server.wasm', input_data['new_b']),
        export(right, 'HEAD', conflict_path, 'resolution/received-conflict.wasm', input_data['new_a']),
    ]
    require(regular(left / B) == dirty_bytes and pin(left / '.uwgit/index') == supplied_index, 'remote operations discarded the original dirty worktree or staged resolution')

    run('restore', left, '--source', 'HEAD', B)
    require(regular(left / B) == resolved_files[B], 'explicit restore did not restore staged module bytes')
    run('mv', left, child_path, A)
    reverse_files = {A: input_data['old_a'], B: input_data['new_b'], conflict_path: input_data['new_a']}
    reverse_tip = staged_commit(left, 'reverse the reviewed directory to an original module file')
    run('push', left)
    run('pull', right, 'origin', 'main', '-m', 'receive reviewed directory to file conversion')
    reverse_commit_pin = shown_commit(right, 'HEAD', reverse_tip, [merged_tip])
    require((right / A).is_file() and not (right / child_path).exists() and all(regular(right / name) == data for name, data in reverse_files.items()), 'SSH pull did not apply exact directory-to-file bytes')
    resolution_exports.append(export(right, 'HEAD', A, 'resolution/received-reverse.wasm', input_data['old_a']))
    prefix_diff_path = run('diff', merged_tip, reverse_tip, '--repo', resolution_upstream, '--format', 'json')
    prefix_diff = json.loads(prefix_diff_path.read_bytes())
    require(prefix_diff['kind'] == 'tree_diff' and {row['path']: row['status'] for row in prefix_diff['files']} == {A: 'added', child_path: 'deleted', B: 'unchanged', conflict_path: 'unchanged'}, 'prefix conversion was not audited as exact path deletion and addition')

    # Change different existing paths to guarantee two divergent tips without
    # assuming anything beyond the admitted old_a/new_a byte distinction.
    write(left, conflict_path, input_data['old_a'])
    run('add', left, conflict_path)
    empty_left_tip = staged_commit(left, 'left diverges before explicit empty-tree resolution')
    write(right, A, input_data['new_a'])
    run('add', right, A)
    empty_right_tip = staged_commit(right, 'right diverges before explicit empty-tree resolution')
    empty_left_files = {**reverse_files, conflict_path: input_data['old_a']}
    empty_right_files = {**reverse_files, A: input_data['new_a']}
    run('push', right)
    empty_left_refs = local_refs(left)
    empty_left_index = pin(left / '.uwgit/index')
    empty_left_worktree = worktree_snapshot(left)
    run('fetch', left)
    require(local_refs(left) == empty_left_refs and pin(left / '.uwgit/index') == empty_left_index and worktree_snapshot(left) == empty_left_worktree, 'fetch before empty resolution changed local state')
    run('rm', left, '--cached', A, B, conflict_path)
    empty_index_data = regular(left / '.uwgit/index')
    require(empty_index_data.startswith(b'UWGITIDX\x02') and json.loads(empty_index_data[9:])['files'] == {}, 'empty resolution must use a real, present, empty index')
    empty_index_pin = pin(left / '.uwgit/index')
    empty_retained_worktree = worktree_snapshot(left)
    empty_report_path = run('merge', left, empty_right_tip, '-m', 'review exact empty staged tree with both ROS parents', '--resolved-index', '--expect-head', empty_left_tip)
    empty_report = json.loads(empty_report_path.read_bytes())
    empty_evidence = resolution_evidence(empty_report, reverse_files, empty_left_files, empty_right_files, {})
    merged_empty_tip = immutable_id(empty_report['commit'])
    require(empty_report['old_head'] == empty_left_tip and empty_report['target'] == empty_right_tip and empty_report['base'] == reverse_tip, 'empty manual resolution changed reviewed ancestry')
    require(pin(left / '.uwgit/index') == empty_index_pin and worktree_snapshot(left) == empty_retained_worktree, 'empty resolution changed index or retained worktree bytes')
    empty_commit_pin = shown_commit(left, 'HEAD', merged_empty_tip, [empty_left_tip, empty_right_tip])
    run('push', left)
    run('pull', right, 'origin', 'main', '-m', 'receive explicit empty-tree merge')
    require(all(not (right / name).exists() for name in reverse_files), 'empty resolved tree left tracked paths in the receiving worktree')
    received_empty_index = regular(right / '.uwgit/index')
    require(received_empty_index.startswith(b'UWGITIDX\x02') and json.loads(received_empty_index[9:])['files'] == {}, 'pull did not synchronize a real empty index')
    resolved_empty_clone = resolution_root / 'empty-clone'
    run('clone', resolution_url, resolved_empty_clone)
    empty_inspection_path = run('inspect', 'HEAD', '--repo', resolved_empty_clone, '--json')
    empty_inspection = json.loads(empty_inspection_path.read_bytes())
    require(empty_inspection['kind'] == 'tree_inspect' and empty_inspection['file_count'] == 0 and empty_inspection['files'] == [], 'SSH clone lost the explicitly resolved empty tree')
    cloned_empty_pin = shown_commit(resolved_empty_clone, 'HEAD', merged_empty_tip, [empty_left_tip, empty_right_tip])
    cloned_merge_pin = shown_commit(resolved_empty_clone, merged_tip, merged_tip, [left_tip, right_tip])
    for repository in [resolution_work, resolution_upstream, left, right, resolved_empty_clone]:
        run('fsck', repository)
    require(all(not row['timed_out'] and row['exit_code'] == row['expected_exit'] for row in commands), 'a command result differs from its explicit expected exit')
    expected_conflicts = [index for index, row in enumerate(commands) if row['expected_exit'] != 0]
    require(expected_conflicts == [conflict_command] and commands[conflict_command]['expected_exit'] == 2, 'only the specified add/add pull may expect a content conflict')
    resolution_summary = {
        'name': 'reviewed_index_prefix_and_empty_tree', 'passed': True,
        'commands': len(commands) - original_commands, 'command_start': original_commands, 'command_end_exclusive': len(commands),
        'repository': str(resolution_upstream), 'local_repositories': [str(repository) for repository in [resolution_work, left, right, resolved_empty_clone]],
        'input_names': sorted(input_data), 'exports': resolution_exports,
        'expected_conflict': {'command_index': conflict_command, 'expected_exit': 2, 'exit_code': commands[conflict_command]['exit_code'], 'report': pin(conflict_report_path)},
        'commits': {'base': resolution_base, 'left': left_tip, 'right': right_tip, 'resolved': merged_tip, 'reverse': reverse_tip, 'empty_left': empty_left_tip, 'empty_right': empty_right_tip, 'empty_resolved': merged_empty_tip},
        'manual_reports': [pin(manual_report_path), pin(empty_report_path)], 'manual_evidence': [first_evidence, empty_evidence],
        'commit_reports': [manual_commit_pin, received_merge_pin, reverse_commit_pin, empty_commit_pin, cloned_empty_pin, cloned_merge_pin],
        'prefix_diff': pin(prefix_diff_path), 'empty_inspection': pin(empty_inspection_path),
        'supplied_index_preserved': True, 'dirty_worktree_preserved': True,
        'fetch_preserved_local_refs_index_and_worktree': True, 'raw_original_module_bytes_only': True,
    }
    inputs_after = {name: pin(path) for name, path in sources.items()}
    require(inputs_after == inputs_before, 'reference inputs changed')
    require(pin(args.binary) == binary_before and pin(Path(__file__).absolute()) == script_before, 'binary or test source changed')
    require(Path('/proc/self/cgroup').read_text() == membership, 'cgroup changed')
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot, 'boot changed')
    limits_after = {field: (cg / field).read_text().strip() for field in limits}
    swap_current_after = (cg / 'memory.swap.current').read_text().strip()
    require(limits_after == limits and limits_after['memory.swap.max'] == swap_max, 'resource limits changed')
    events_after = counters((cg / 'memory.events').read_text())
    delta = {key: events_after.get(key, 0) - events_before.get(key, 0) for key in sorted(events_before.keys() | events_after.keys())}
    memory = {'before': events_before, 'after': events_after, 'delta': delta, 'policy': 'Only OOM counter growth fails. Other memory events may reflect load in this shared cgroup; other tasks are not isolated.'}
    (args.output / 'memory-events.json').write_text(json.dumps(memory, indent=2) + '\n')
    for key in ['oom', 'oom_kill', 'oom_group_kill']:
        require(key in events_before and key in events_after and delta[key] <= 0, 'OOM counter grew or is missing: ' + key)
    summary = {'passed': True, 'transport': 'actual parent OpenSSH loopback service', 'commands': len(commands), 'original_workflow_commands': original_commands, 'workflows': [{'name': 'original_multi_module', 'passed': True, 'commands': original_commands, 'command_start': 0, 'command_end_exclusive': original_commands}, resolution_summary], 'script': script_before, 'binary': binary_before, 'inputs_before': inputs_before, 'input_copies': input_pins, 'inputs_after': inputs_after, 'exports': exports, 'tree_commits': {'initial': initial, 'changed': changed, 'empty': empty_tip}, 'diffs': [pin(tree_diff_path), pin(single_diff_path)], 'fetch_preserved_local_refs_index_and_worktree': True, 'cgroup': expected, 'boot_id': boot, 'expected_cgroup_swap_max': swap_max, 'limits_before': limits, 'limits_after': limits_after, 'swap_current_before': swap_current_before, 'swap_current_after': swap_current_after, 'memory_events': memory, 'fuzzer_run': False}
    (resolution_root / 'summary.json').write_text(json.dumps(resolution_summary, indent=2) + '\n')
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
