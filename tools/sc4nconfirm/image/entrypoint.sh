#!/bin/sh
# Plant the canaries, then run the loader under strace.
#
# The canaries are the point: a payload that harvests credentials reads a path
# that looks exactly like a real one, and the trace records the attempt. They are
# written here rather than baked into the image so the image stays publishable and
# the sentinel value is obviously not a credential.
#
# The entrypoint stays root only long enough to plant canaries and run the root
# strace tracer. load.py drops to uid 65534 before it opens the artifact, so the
# payload cannot write the root-owned /out or the tracer's /tmp/trace.
set -u

mkdir -p /home/worker/.cache/huggingface /home/worker/.ssh /home/worker/DOCUMENTS \
         /home/worker/.aws 2>/dev/null || true

echo "sc4nconfirm-canary-not-a-real-token" > /home/worker/.cache/huggingface/token
echo "sc4nconfirm-canary-not-a-real-key"   > /home/worker/.ssh/id_rsa
echo "sc4nconfirm-canary-not-a-real-key"   > /home/worker/.ssh/id_ed25519
echo "sc4nconfirm-canary-not-a-real-id"    > /home/worker/DOCUMENTS/id.txt
echo "sc4nconfirm-canary-not-real-creds"   > /home/worker/.aws/credentials
echo "machine example.invalid login sc4nconfirm-canary password none" > /home/worker/.netrc

# Hand the canaries to the payload identity; root keeps /out.
chown -R 65534:65534 /home/worker 2>/dev/null || true

mkdir -p /out /tmp 2>/dev/null || true

# -qq: no attach/detach noise. -s 512: enough argv to name what ran.
# -f: follow the payload's children, which is where a shell ends up.
# Do not exec: the shell must survive the tracer to copy the evidence out.
strace -f -qq -o /tmp/trace -s 512 \
     -e trace=execve,execveat,open,openat,openat2,connect \
     python3 /opt/sc4nconfirm/load.py "$@"
rc=$?

cp /tmp/trace /out/trace 2>/dev/null || true
cp /tmp/result.json /out/result.json 2>/dev/null || true
exit "$rc"
