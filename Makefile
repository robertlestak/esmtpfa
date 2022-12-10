bin: bin/esmtpfa_darwin bin/esmtpfa_linux

.PHONY: envvars
envvars:
	@egrep -oh --exclude Makefile \
		--exclude-dir bin \
		--exclude-dir scripts \
		-R 'os.Getenv\(.*?\)' . | \
		tr -d ' ' | \
		sort | \
		uniq | \
		sed -e 's,os.Getenv(,,g' -e 's,),,g' \
		-e 's,",,g'

.env-sample:
	$(MAKE) envvars > .env-sample
	sed 's/$$/=/' .env-sample > .env-sample.tmp && mv .env-sample.tmp .env-sample

bin/esmtpfa_darwin:
	mkdir -p bin
	GOOS=darwin GOARCH=amd64 go build -o bin/esmtpfa_darwin cmd/esmtpfa/*.go
	openssl sha512 bin/esmtpfa_darwin | awk '{print $$2}' > bin/esmtpfa_darwin.sha512

bin/esmtpfa_linux:
	mkdir -p bin
	GOOS=linux GOARCH=amd64 go build -o bin/esmtpfa_linux cmd/esmtpfa/*.go
	openssl sha512 bin/esmtpfa_linux | awk '{print $$2}' > bin/esmtpfa_linux.sha512
