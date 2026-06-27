set -eu
cat >/tmp/t.c <<'EOF'
#include <stdio.h>
#include <unistd.h>
int main() {
  for (int i = 0; i < 5; i++) {
    printf("hello %d\n", i);
    fflush(stdout);
    sleep(1);
  }
  return 0;
}
EOF
gcc /tmp/t.c -o /tmp/t
/tmp/t >/tmp/t.out 2>&1 &
pid=$!
mkdir -p /sys/kernel/debug /sys/kernel/tracing 2>/dev/null || true
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
timeout 4 bpftrace /sentinel-ebpf/monitor.bt "$pid" >/tmp/bt.log 2>&1 || true
wait "$pid" || true
echo ===BT===
cat /tmp/bt.log
echo ===OUT===
cat /tmp/t.out
