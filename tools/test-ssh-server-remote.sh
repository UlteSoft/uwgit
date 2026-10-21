#!/usr/bin/env bash
# Execute only inside the already admitted SSH Linux cgroup. No system SSH
# configuration, account, key, or known-host file is changed. All test material
# lives in a newly reserved /tmp directory; private test keys are removed on exit.
set -euo pipefail
if [[ $# != 2 ]]; then
    echo 'usage: test-ssh-server-remote.sh /absolute/wasm-git /tmp/uwgit-ssh-server-NEW' >&2
    exit 2
fi
binary=$1
work=$2
case "$binary" in /*) ;; *) echo 'binary must be an absolute path' >&2; exit 2 ;; esac
if [[ ! "$work" =~ ^/tmp/uwgit-ssh-server-[A-Za-z0-9_-]+$ ]]; then
    echo 'test directory must be a simple /tmp/uwgit-ssh-server-NAME path' >&2
    exit 2
fi
: "${UWGIT_EXPECTED_CGROUP:?exact admitted /proc/self/cgroup path is required}"
: "${UWGIT_EXPECTED_BOOT_ID:?admitted boot ID is required}"
mkdir -m 700 "$work"
mkdir "$work/logs" "$work/repositories"
sshd_pid=
cleanup() {
    local result=$?
    trap - EXIT INT TERM
    if [[ -n "$sshd_pid" ]]; then
        kill "$sshd_pid" 2>/dev/null || true
        wait "$sshd_pid" 2>/dev/null || true
    fi
    rm -f "$work/client-key" "$work/host-key"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
python3 - "$work/admission.json" "$binary" <<'PY'
import hashlib,json,os,pathlib,platform,sys
assert platform.system()=='Linux'
expected=os.environ['UWGIT_EXPECTED_CGROUP']
lines=pathlib.Path('/proc/self/cgroup').read_text().splitlines()
assert lines==['0::'+expected], lines
assert 'docker-' in expected and expected.endswith('.scope'), expected
base=pathlib.Path('/sys/fs/cgroup')
# /host chroot retains the full cgroup tree, rather than a namespace-rebased root.
base=base/expected.lstrip('/')
swap_max=os.environ.get('UWGIT_EXPECTED_CGROUP_SWAP_MAX','0')
assert swap_max in ('max','0') or (swap_max and swap_max[0] in '123456789' and all(char in '0123456789' for char in swap_max)),'UWGIT_EXPECTED_CGROUP_SWAP_MAX must be max or canonical nonnegative decimal'
values={name:(base/name).read_text().strip() for name in ['memory.max','memory.swap.max','memory.swap.current','cpuset.cpus.effective','memory.events']}
assert values['memory.max']=='68719476736',values
assert values['memory.swap.max']==swap_max,values
assert values['cpuset.cpus.effective']=='0-31',values
boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
assert boot==os.environ['UWGIT_EXPECTED_BOOT_ID'],boot
binary=pathlib.Path(sys.argv[2]); assert binary.is_file() and os.access(binary,os.X_OK)
record={'boot_id':boot,'cgroup':expected,'expected_cgroup_swap_max':swap_max,'resources':values,'binary':str(binary),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'fuzzer_run':False}
pathlib.Path(sys.argv[1]).write_text(json.dumps(record,sort_keys=True)+'\n')
PY
sshd=$(command -v sshd || true)
if [[ -z "$sshd" && -x /usr/sbin/sshd ]]; then sshd=/usr/sbin/sshd; fi
[[ -n "$sshd" ]] || { echo 'sshd is unavailable in the admitted test environment' >&2; exit 1; }
ssh_binary=$(command -v ssh)
ssh_keygen=$(command -v ssh-keygen)
username=$(id -un)
"$ssh_keygen" -q -t ed25519 -N '' -f "$work/host-key" >"$work/logs/host-key.stdout" 2>"$work/logs/host-key.stderr"
"$ssh_keygen" -q -t ed25519 -N '' -f "$work/client-key" >"$work/logs/client-key.stdout" 2>"$work/logs/client-key.stderr"
cp "$work/client-key.pub" "$work/authorized_keys"
chmod 600 "$work/authorized_keys"
port=$(python3 - <<'PY'
import socket
with socket.socket() as listener:
    listener.bind(('127.0.0.1',0))
    print(listener.getsockname()[1])
PY
)
cat > "$work/sshd_config" <<CONFIG
Port $port
ListenAddress 127.0.0.1
HostKey $work/host-key
PidFile $work/sshd.pid
AuthorizedKeysFile $work/authorized_keys
AllowUsers $username
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PermitRootLogin prohibit-password
StrictModes no
PermitUserEnvironment no
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
GatewayPorts no
PrintMotd no
LogLevel VERBOSE
CONFIG
python3 - "$work" "$port" <<'PY'
import pathlib,sys
root=pathlib.Path(sys.argv[1]);public=(root/'host-key.pub').read_text().split()
(root/'known_hosts').write_text('[127.0.0.1]:'+sys.argv[2]+' '+public[0]+' '+public[1]+'\n')
PY
cat > "$work/ssh_config" <<CONFIG
Host *
  IdentityFile $work/client-key
  UserKnownHostsFile $work/known_hosts
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking yes
  IdentitiesOnly yes
  BatchMode yes
  PasswordAuthentication no
  KbdInteractiveAuthentication no
  ProxyCommand none
  LogLevel ERROR
CONFIG
cat > "$work/ssh-program" <<'SHIM'
#!/bin/sh
set -eu
exec "$UWGIT_TEST_SSH_BINARY" -F "$UWGIT_TEST_SSH_CONFIG" "$@"
SHIM
chmod 700 "$work/ssh-program"
# This isolated daemon must accept fixtures under the world-writable /tmp
# parent. Compensate for its temporary StrictModes=no by checking the freshly
# reserved private directory and every private key/authorization file ourselves.
python3 - "$work" <<'PY'
import json,os,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]);uid=os.geteuid();records=[]
for name,mode,directory in [('',0o700,True),('client-key',0o600,False),('host-key',0o600,False),('authorized_keys',0o600,False),('ssh-program',0o700,False)]:
    path=root/name;metadata=path.lstat()
    assert not stat.S_ISLNK(metadata.st_mode),'fixture must not be a symlink'
    assert metadata.st_uid==uid,'fixture must belong to the test runner'
    assert stat.S_IMODE(metadata.st_mode)==mode,'fixture permission mismatch'
    assert stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode),'fixture file type mismatch'
    records.append({'path':str(path),'uid':metadata.st_uid,'mode':oct(mode),'directory':directory})
(root/'fixture-protection.json').write_text(json.dumps({'uid':uid,'checked':records,'test_daemon_strict_modes':False,'reason':'The isolated test daemon reads authorized_keys under the required world-writable /tmp parent; its newly reserved directory is owned by the runner with mode 0700 and private keys/authorized_keys are owned by the runner with mode 0600.'},sort_keys=True)+'\n')
PY
"$sshd" -t -f "$work/sshd_config" >"$work/logs/sshd-check.stdout" 2>"$work/logs/sshd-check.stderr"
"$sshd" -D -e -f "$work/sshd_config" >"$work/logs/sshd.stdout" 2>"$work/logs/sshd.stderr" &
sshd_pid=$!
python3 - "$port" <<'PY'
import socket,sys,time
limit=time.monotonic()+5
while True:
    try:
        with socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=.25):break
    except OSError:
        if time.monotonic()>=limit:raise
        time.sleep(.025)
PY
export UWGIT_SSH_PROGRAM="$work/ssh-program"
export UWGIT_TEST_SSH_BINARY="$ssh_binary"
export UWGIT_TEST_SSH_CONFIG="$work/ssh_config"
export UWGIT_REMOTE_PROGRAM="$binary"
unset UWGIT_REMOTE_TOKEN || true
sequence=0
run() {
    sequence=$((sequence+1))
    local result=0
    "$@" >"$work/logs/$sequence.stdout" 2>"$work/logs/$sequence.stderr" || result=$?
    python3 - "$work" "$sequence" "$result" "$@" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]);sequence=int(sys.argv[2]);record={'sequence':sequence,'argv':sys.argv[4:],'exit_code':int(sys.argv[3])}
for name in ['stdout','stderr']:
    path=root/'logs'/f'{sequence}.{name}';data=path.read_bytes();record[name]={'path':str(path),'length':len(data),'sha256':hashlib.sha256(data).hexdigest()}
with (root/'commands.jsonl').open('a') as f:f.write(json.dumps(record,sort_keys=True)+'\n')
PY
    return "$result"
}
python3 - "$work" <<'PY'
import hashlib,json,os,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]);old=os.environ.get('UWGIT_TEST_SSH_OLD_WASM');new=os.environ.get('UWGIT_TEST_SSH_NEW_WASM')
assert (old is None)==(new is None),'both UWGIT_TEST_SSH_OLD_WASM and UWGIT_TEST_SSH_NEW_WASM must be set together'
provided=old is not None
if provided:assert old and new,'provided input paths must not be empty'
records={}
for label,source,value in [('old',old,1),('new',new,2)]:
    if provided:
        path=pathlib.Path(source)
        assert stat.S_ISREG(path.lstat().st_mode),'provided input must be a regular non-symlink file'
        data=path.read_bytes()
    else:
        data=b'\x00asm\x01\x00\x00\x00'+bytes([0,3,1,120,value])
    assert data.startswith(b'\x00asm\x01\x00\x00\x00'),'input must have the Core Wasm module header'
    digest=hashlib.sha256(data).hexdigest()
    destination=root/(label+'.wasm')
    with destination.open('xb') as output:output.write(data)
    assert destination.read_bytes()==data
    if provided:
        assert stat.S_ISREG(path.lstat().st_mode),'input ceased to be a regular file while copying'
        after=hashlib.sha256(path.read_bytes()).hexdigest()
        assert after==digest,'input bytes changed while copying'
    else:after=digest
    records[label]={'path':str(destination),'source_path':source,'length':len(data),'sha256_before_copy':digest,'sha256_after_copy':after,'snapshot_sha256':hashlib.sha256(destination.read_bytes()).hexdigest()}
assert records['old']['snapshot_sha256']!=records['new']['snapshot_sha256'],'old and new inputs must differ'
(root/'input-pins.json').write_text(json.dumps({'format':1,'mode':'provided-core-modules' if provided else 'fixed-handwritten-modules','inputs':records},sort_keys=True)+'\n')
PY
upstream="$work/repositories/upstream"
local_clone="$work/client"
url="ssh://$username@127.0.0.1:$port$work/repositories/upstream"
run "$binary" init "$upstream"
run "$binary" commit "$upstream" "$work/old.wasm" -m 'SSH initial commit'
run "$binary" branch "$upstream" feature
run "$binary" tag "$upstream" v1
run "$binary" clone "$url" "$local_clone"
run "$binary" show "$local_clone" HEAD
run "$binary" show "$local_clone" HEAD --output "$work/cloned-old.wasm"
run "$binary" commit "$local_clone" "$work/new.wasm" -m 'SSH pushed original bytes'
run "$binary" push "$local_clone"
run "$binary" show "$upstream" HEAD
run "$binary" show "$upstream" HEAD --output "$work/pushed-new.wasm"
run "$binary" fetch "$local_clone"
run "$binary" pull "$local_clone" origin main -m 'SSH already integrated'
run "$binary" show "$local_clone" origin/main
run "$binary" fsck "$upstream"
run "$binary" fsck "$local_clone"
# The default single-module workflow stays unchanged. Supplying any tree input
# enables one additional, separately logged workflow on this same real daemon.
if [[ -n ${UWGIT_TEST_SSH_TREE_OLD_A+x} || -n ${UWGIT_TEST_SSH_TREE_OLD_B+x} || -n ${UWGIT_TEST_SSH_TREE_NEW_A+x} || -n ${UWGIT_TEST_SSH_TREE_NEW_B+x} ]]; then
    : "${UWGIT_TEST_SSH_TREE_OLD_A:?all four tree module inputs are required}"
    : "${UWGIT_TEST_SSH_TREE_OLD_B:?all four tree module inputs are required}"
    : "${UWGIT_TEST_SSH_TREE_NEW_A:?all four tree module inputs are required}"
    : "${UWGIT_TEST_SSH_TREE_NEW_B:?all four tree module inputs are required}"
    tree_script="$(cd "$(dirname "$0")" && pwd)/test-tree-ssh-workflow.py"
    python3 - "$tree_script" "$work/tree-hook-source.json" <<'PY'
import hashlib,json,pathlib,stat,sys
path=pathlib.Path(sys.argv[1]);assert stat.S_ISREG(path.lstat().st_mode)
data=path.read_bytes()
pathlib.Path(sys.argv[2]).write_text(json.dumps({'path':str(path),'byte_len':len(data),'sha256':hashlib.sha256(data).hexdigest()},sort_keys=True)+'\n')
PY
    python3 "$tree_script" "$binary" --root "$work/repositories" --authority "$username@127.0.0.1:$port" \
        --old-a "$UWGIT_TEST_SSH_TREE_OLD_A" --old-b "$UWGIT_TEST_SSH_TREE_OLD_B" \
        --new-a "$UWGIT_TEST_SSH_TREE_NEW_A" --new-b "$UWGIT_TEST_SSH_TREE_NEW_B" \
        --output "$work/tree-workflow" >"$work/logs/tree-workflow.stdout" 2>"$work/logs/tree-workflow.stderr"
fi
python3 - "$work" "$binary" <<'PY'
import hashlib,json,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]);records=[json.loads(line) for line in (root/'commands.jsonl').read_text().splitlines()]
assert len(records)==16 and all(row['exit_code']==0 for row in records),records
read=lambda n:json.loads((root/'logs'/f'{n}.stdout').read_bytes())
assert read(6)['id']!=read(10)['id']
assert read(10)['id']==read(14)['id']
assert read(15)['commits']==2 and read(16)['commits']==2
pins=json.loads((root/'input-pins.json').read_text())
for label,export_name in [('old','cloned-old.wasm'),('new','pushed-new.wasm')]:
    record=pins['inputs'][label];snapshot=pathlib.Path(record['path']).read_bytes();exported=(root/export_name).read_bytes()
    assert len(snapshot)==record['length'] and snapshot==exported
    assert hashlib.sha256(snapshot).hexdigest()==record['snapshot_sha256']==record['sha256_before_copy']==record['sha256_after_copy']
    if record['source_path'] is not None:
        path=pathlib.Path(record['source_path']);assert stat.S_ISREG(path.lstat().st_mode)
        assert hashlib.sha256(path.read_bytes()).hexdigest()==record['snapshot_sha256'],'provided source changed during the SSH workflow'
    record['verified_export']={'path':str(root/export_name),'length':len(exported),'sha256':hashlib.sha256(exported).hexdigest()}
admission=json.loads((root/'admission.json').read_text());binary=pathlib.Path(sys.argv[2])
assert hashlib.sha256(binary.read_bytes()).hexdigest()==admission['binary_sha256']
assert pathlib.Path('/proc/self/cgroup').read_text().splitlines()==['0::'+admission['cgroup']]
assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==admission['boot_id']
base=pathlib.Path('/sys/fs/cgroup')/admission['cgroup'].lstrip('/')
resources_after={field:(base/field).read_text().strip() for field in ['memory.max','memory.swap.max','cpuset.cpus.effective']}
assert resources_after=={field:admission['resources'][field] for field in resources_after},resources_after
assert resources_after['memory.swap.max']==admission['expected_cgroup_swap_max'],resources_after
swap_current_after=(base/'memory.swap.current').read_text().strip()
after=(base/'memory.events').read_text().strip()
before_events={name:int(value) for name,value in (line.split() for line in admission['resources']['memory.events'].splitlines())}
after_events={name:int(value) for name,value in (line.split() for line in after.splitlines())}
event_delta={name:after_events.get(name,0)-before_events.get(name,0) for name in sorted(before_events.keys()|after_events.keys())}
event_record={'before':before_events,'after':after_events,'delta':event_delta,'policy':'Only growth in oom, oom_kill or oom_group_kill fails the test. Nonfatal memory.max events may reflect other load in this shared cgroup; this run does not isolate other tasks.'}
(root/'memory-events.json').write_text(json.dumps(event_record,sort_keys=True)+'\n')
for name in ['oom','oom_kill','oom_group_kill']:
    assert name in before_events and name in after_events,'required OOM event counter missing: '+name
    assert event_delta[name]<=0,'OOM event counter increased: '+name
fixture_protection=json.loads((root/'fixture-protection.json').read_text())
for record in fixture_protection['checked']:
    metadata=pathlib.Path(record['path']).lstat()
    assert not stat.S_ISLNK(metadata.st_mode) and metadata.st_uid==record['uid']
    assert oct(stat.S_IMODE(metadata.st_mode))==record['mode']
    assert stat.S_ISDIR(metadata.st_mode) if record['directory'] else stat.S_ISREG(metadata.st_mode)
tree_workflow=None
if (root/'tree-hook-source.json').exists():
    source=json.loads((root/'tree-hook-source.json').read_text());script=pathlib.Path(source['path'])
    assert stat.S_ISREG(script.lstat().st_mode)
    script_bytes=script.read_bytes();assert len(script_bytes)==source['byte_len'] and hashlib.sha256(script_bytes).hexdigest()==source['sha256']
    summary_path=root/'tree-workflow/summary.json';summary_bytes=summary_path.read_bytes();child=json.loads(summary_bytes)
    assert child['passed'] is True and child['fuzzer_run'] is False and child['commands']>0
    assert child['script']==source and child['binary']['sha256']==admission['binary_sha256']
    assert child['expected_cgroup_swap_max']==admission['expected_cgroup_swap_max']
    tree_workflow={'summary':child,'summary_path':str(summary_path),'summary_sha256':hashlib.sha256(summary_bytes).hexdigest(),'source':source}
summary={'passed':True,'transport':'actual OpenSSH loopback daemon with temporary keys and pinned known_hosts','commands':len(records),'total_product_commands':len(records)+(tree_workflow['summary']['commands'] if tree_workflow else 0),'tree_workflow':tree_workflow,'input_pins':pins,'test_daemon_strict_modes':False,'fixture_protection':fixture_protection,'source_and_runtime_environment':'existing admitted SSH Linux cgroup','binary_sha256':admission['binary_sha256'],'cgroup':admission['cgroup'],'boot_id':admission['boot_id'],'expected_cgroup_swap_max':admission['expected_cgroup_swap_max'],'swap_current_before':admission['resources']['memory.swap.current'],'swap_current_after':swap_current_after,'fuzzer_run':False,'resources_after':resources_after,'memory_events_before':admission['resources']['memory.events'],'memory_events_after':after,'memory_events':event_record}
(root/'summary.json').write_text(json.dumps(summary,sort_keys=True)+'\n')
print(json.dumps(summary,sort_keys=True))
PY
