UNAME   := $(shell uname -s)
CC       = cc
CFLAGS   = -Wall -Wextra -std=c11 -O2 -Iinclude
SRCS     = src/rocei_pkcs11.c
HDRS     = src/pkcs11_platform.h include/pkcs11.h include/pkcs11t.h include/pkcs11f.h

ifeq ($(UNAME), Darwin)
  CC      = clang
  TARGET  = rocei_pkcs11.dylib
  LDFLAGS = -dynamiclib -framework PCSC
else ifeq ($(UNAME), Linux)
  TARGET  = rocei_pkcs11.so
  CFLAGS += -fPIC $(shell pkg-config --cflags libpcsclite openssl 2>/dev/null)
  LDFLAGS = -shared $(shell pkg-config --libs libpcsclite openssl 2>/dev/null || echo "-lpcsclite -lssl -lcrypto")
else
  # Windows (MinGW / MSYS2)
  TARGET  = rocei_pkcs11.dll
  LDFLAGS = -shared -lwinscard -lcrypto
endif

SMOKE = p11_smoke

$(TARGET): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

$(SMOKE): tools/p11_smoke.c $(HDRS)
	$(CC) $(CFLAGS) -o $@ tools/p11_smoke.c

clean:
	rm -f $(TARGET) $(SMOKE)

.PHONY: clean
