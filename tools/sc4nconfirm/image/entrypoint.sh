#!/bin/sh
# Plant the canaries, then run the loader under strace.
#
# The canaries are the point: a payload that harvests credentials reads a path
# that looks exactly like a real one, and the trace records the attempt. They are
# written here rather than baked into the image so the image stays publishable and
# the sentinel value is obviously not a credential.
set -u

mkdir -p /home/worker/.cache/huggingface /home/worker/.ssh /home/worker/DOCUMENTS \
         /home/worker/.aws 2>/dev/null || true

echo "sc4nconfirm-canary-not-a-real-token" > /home/worker/.cache/huggingface/token
echo "sc4nconfirm-canary-not-a-real-key"   > /home/worker/.ssh/id_rsa
echo "sc4nconfirm-canary-not-a-real-key"   > /home/worker/.ssh/id_ed25519
echo "sc4nconfirm-canary-not-a-real-id"    > /home/worker/DOCUMENTS/id.txt
echo "sc4nconfirm-canary-not-real-creds"   > /home/worker/.aws/credentials
echo "machine example.invalid login sc4nconfirm-canary password none" > /home/worker/.netrc

mkdir -p /out /tmp 2>/dev/null || true

# -qq: no attach/detach noise. -s 512: enough argv to name what ran.
# -f: follow the payload's children, which is where a shell ends up.
exec strace -f -qq -o /out/trace -s 512 \
     -e trace=execve,execveat,open,openat,openat2,connect \
     python3 /opt/sc4nconfirm/load.py "$@"
