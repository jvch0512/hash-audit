build:
	mkdir -p bin && ldc2 -O -of=bin/hash-audit src/hashaudit.d src/app.d

test: build
	mkdir -p build && ldc2 -unittest -of=build/test tests/test.d src/hashaudit.d && ./build/test && sh tests/cli.sh

sample: build
	mkdir -p docs site
	./bin/hash-audit examples/shadow.sample examples/htpasswd.sample > docs/sample-output.txt; true
	./bin/hash-audit examples/shadow.sample examples/htpasswd.sample --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "hash-audit" "Audits password hash files (/etc/shadow, htpasswd) for weak algorithms, empty passwords and reuse. D." "Synthetic accounts with invented hash strings."
