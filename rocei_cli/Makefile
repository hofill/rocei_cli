UNAME   := $(shell uname -s)
CC       = cc
CFLAGS   = -Wall -Wextra -std=c11 -O2
SRCS     = src/main.c src/card.c src/apdu.c

ifeq ($(UNAME), Darwin)
  CC      = clang
  TARGET  = rocei
  LDFLAGS = -framework PCSC
else ifeq ($(UNAME), Linux)
  TARGET  = rocei
  CFLAGS += $(shell pkg-config --cflags libpcsclite openssl 2>/dev/null)
  LDFLAGS  = $(shell pkg-config --libs libpcsclite openssl 2>/dev/null || echo "-lpcsclite -lcrypto")
else
  # Windows (MinGW / MSYS2)
  TARGET  = rocei.exe
  LDFLAGS = -lwinscard -lcrypto
endif

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f rocei rocei.exe

.PHONY: clean
