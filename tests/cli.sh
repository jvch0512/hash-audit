#!/bin/sh
cd "$(dirname "$0")/.." || exit 1
pass=0; fail=0
ok() { if [ "$1" = 0 ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $2"; fi; }
B=./bin/hash-audit
[ -x $B ] || { mkdir -p bin && ldc2 -O -of=$B src/hashaudit.d src/app.d || exit 1; }
$B examples/shadow.sample >/dev/null; [ $? -eq 0 ]; ok $? "exit 0 by default"
$B examples/shadow.sample --fail-on critical >/dev/null; [ $? -eq 1 ]; ok $? "fail-on critical"
$B examples/shadow.sample --fail-on high >/dev/null; [ $? -eq 1 ]; ok $? "fail-on high"
printf 'a:$y$j9T$s$h:1::::::\n' > /tmp/ha-clean.$$
$B /tmp/ha-clean.$$ --fail-on medium >/dev/null; [ $? -eq 0 ]; ok $? "clean file passes"
printf 'a:$2y$05$%s:1::::::\n' "$(printf 'a%.0s' $(seq 53))" > /tmp/ha-med.$$
$B /tmp/ha-med.$$ --fail-on high >/dev/null; [ $? -eq 0 ]; ok $? "medium does not trip high"
$B /tmp/ha-med.$$ --fail-on medium >/dev/null; [ $? -eq 1 ]; ok $? "medium trips medium"
rm -f /tmp/ha-clean.$$ /tmp/ha-med.$$
$B /no/such/file >/dev/null 2>&1; [ $? -eq 2 ]; ok $? "missing file"
$B >/dev/null 2>&1; [ $? -eq 2 ]; ok $? "no args"
$B examples/shadow.sample --bogus >/dev/null 2>&1; [ $? -eq 2 ]; ok $? "bad flag"
$B examples/shadow.sample --fail-on nope >/dev/null 2>&1; [ $? -eq 2 ]; ok $? "bad fail-on"
$B examples/shadow.sample --tsv | head -1 | grep -q '^# 1 files, 11 accounts'; ok $? "tsv summary"
! $B examples/shadow.sample examples/htpasswd.sample | grep -qE 'hunter2|\$apr1\$[A-Za-z./0-9]{8}\$'; ok $? "no hash material printed"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
