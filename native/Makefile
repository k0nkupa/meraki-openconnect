CC := /usr/bin/clang
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Werror -I. -I/opt/homebrew/include
LDFLAGS := -L/opt/homebrew/lib -Wl,-headerpad_max_install_names -lopenconnect -lgnutls

.PHONY: all clean smoke test

all: tests/test_protocol tests/test_policy meraki-openconnect-native

tests/test_protocol: tests/test_protocol.c protocol.c protocol.h policy.c policy.h worker_io.c worker_io.h
	$(CC) $(CFLAGS) tests/test_protocol.c protocol.c policy.c worker_io.c $(LDFLAGS) -o $@

tests/test_policy: tests/test_policy.c policy.c policy.h
	$(CC) $(CFLAGS) tests/test_policy.c policy.c $(LDFLAGS) -o $@

meraki-openconnect-native: worker.c protocol.c protocol.h policy.c policy.h worker_io.c worker_io.h
	$(CC) $(CFLAGS) worker.c protocol.c policy.c worker_io.c $(LDFLAGS) -lpthread -o $@

smoke: meraki-openconnect-native
	./meraki-openconnect-native --smoke
	./meraki-openconnect-native --smoke-missing-policy
	./meraki-openconnect-native --smoke-early-signal; STATUS=$$?; test "$$STATUS" -eq 143

test: tests/test_protocol tests/test_policy smoke
	./tests/test_protocol
	./tests/test_policy

clean:
	rm -f tests/test_protocol tests/test_policy meraki-openconnect-native
