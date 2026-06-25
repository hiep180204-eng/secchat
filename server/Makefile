CC      ?= gcc
CLANG   ?= clang
FUZZ_RUNS ?= 10000
FUZZ_SECONDS ?= 300
FUZZ_WORKDIR ?= /tmp/secchat_fuzz
FUZZ_CORPUS ?= $(FUZZ_WORKDIR)/corpus
FUZZ_JSON_CORPUS ?= $(FUZZ_CORPUS)/json_validation
FUZZ_WS_CORPUS ?= $(FUZZ_CORPUS)/ws_frame
FUZZ_ARTIFACTS ?= $(FUZZ_WORKDIR)/artifacts
SAN_RUN_ENV = ASAN_OPTIONS=abort_on_error=0:halt_on_error=1:print_stacktrace=1 UBSAN_OPTIONS=print_stacktrace=1

# Layered directory structure.
# -I. resolves cJSON.h.
# -Itransport / -Iprotocol / -Iinfra let subdirectory .c files find
# their sibling headers without path-qualified includes.
# -Idomain lets domain/*.c files find each other.
CFLAGS  ?= -Wall -Wextra -O2 -pthread \
          -I. -Itransport -Iprotocol -Iinfra -Iservices -Irepository -Idomain \
          $(shell mysql_config --cflags) -Wno-deprecated-declarations
LIBS    = -lssl -lcrypto -lpthread \
          $(shell mysql_config --libs)
SAN_CFLAGS = -Wall -Wextra -O1 -g -pthread \
          -fsanitize=address,undefined -fno-omit-frame-pointer \
          -I. -Itransport -Iprotocol -Iinfra -Iservices -Irepository -Idomain \
          $(shell mysql_config --cflags) -Wno-deprecated-declarations

SRCS    = main.c \
          transport/ws.c transport/clients.c transport/http.c \
          protocol/json_helpers.c \
          infra/config.c infra/log.c infra/crypto.c infra/metrics.c \
          infra/migrate.c infra/db_pool.c infra/db_lifecycle.c \
          services/auth.c services/friends.c \
          services/chat.c \
          services/messaging_service.c \
          services/reaction_service.c \
          services/pin_service.c \
          services/disappearing_service.c \
          services/conv_pref_service.c \
          services/profile.c services/presence.c \
          services/groups.c \
          services/keys.c \
          services/blocking.c \
          services/notifications.c \
          infra/ratelimit.c \
          repository/user_repo.c repository/friendship_repo.c \
          repository/conversation_repo.c repository/message_repo.c \
          repository/key_repo.c \
          repository/block_repo.c repository/notification_repo.c \
          domain/validation.c domain/caller_context.c \
          cJSON.c

OBJS    = $(SRCS:.c=.o)
TARGET  = chat_server

.PHONY: all clean test_domain asan_build asan_test_domain fuzz_json_validation fuzz_ws_frame fuzz_prepare_corpus fuzz_smoke fuzz_long cppcheck

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# S1: compile cJSON with the active CFLAGS but without project warning noise.
cJSON.o: cJSON.c cJSON.h
	$(CC) $(filter-out -Wall -Wextra,$(CFLAGS)) -I. -c -o $@ $<

# Self-contained domain unit tests (no DB, no OpenSSL, <1s)
test_domain: domain/test_domain_unit.c domain/validation.c
	$(CC) -Wall -Wextra -O2 -I. -Idomain \
	    -o /tmp/test_domain_unit \
	    domain/test_domain_unit.c domain/validation.c
	/tmp/test_domain_unit

asan_build:
	$(MAKE) clean
	$(MAKE) CC=$(CLANG) CFLAGS="$(SAN_CFLAGS)" all

asan_test_domain: domain/test_domain_unit.c domain/validation.c
	$(CLANG) -Wall -Wextra -O1 -g -fsanitize=address,undefined \
	    -fno-omit-frame-pointer -I. -Idomain \
	    -o /tmp/test_domain_unit_asan \
	    domain/test_domain_unit.c domain/validation.c
	ASAN_OPTIONS=abort_on_error=0:halt_on_error=1:print_stacktrace=1 /tmp/test_domain_unit_asan

fuzz_json_validation: fuzz/fuzz_json_validation.c protocol/json_helpers.c domain/validation.c transport/ws.c infra/crypto.c infra/metrics.c cJSON.c
	$(CLANG) -DSECCHAT_LIBFUZZER -fsanitize=fuzzer,address,undefined \
	    -fno-omit-frame-pointer -g -O1 \
	    -I. -Itransport -Iprotocol -Iinfra -Iservices -Irepository -Idomain \
	    $(shell mysql_config --cflags) -Wno-deprecated-declarations \
	    -o /tmp/secchat_fuzz_json_validation \
	    fuzz/fuzz_json_validation.c protocol/json_helpers.c domain/validation.c \
	    transport/ws.c infra/crypto.c infra/metrics.c cJSON.c $(LIBS)

fuzz_ws_frame: fuzz/fuzz_ws_frame.c transport/ws.c infra/crypto.c infra/metrics.c
	$(CLANG) -DSECCHAT_LIBFUZZER -fsanitize=fuzzer,address,undefined \
	    -fno-omit-frame-pointer -g -O1 \
	    -I. -Itransport -Iprotocol -Iinfra -Iservices -Irepository -Idomain \
	    $(shell mysql_config --cflags) -Wno-deprecated-declarations \
	    -o /tmp/secchat_fuzz_ws_frame \
	    fuzz/fuzz_ws_frame.c transport/ws.c infra/crypto.c infra/metrics.c $(LIBS)

fuzz_prepare_corpus:
	rm -rf $(FUZZ_WORKDIR)
	mkdir -p $(FUZZ_JSON_CORPUS) $(FUZZ_WS_CORPUS) $(FUZZ_ARTIFACTS)/json_validation $(FUZZ_ARTIFACTS)/ws_frame
	cp -R fuzz/corpus/json_validation/. $(FUZZ_JSON_CORPUS)/
	cp -R fuzz/corpus/ws_frame/. $(FUZZ_WS_CORPUS)/

fuzz_smoke: fuzz_json_validation fuzz_ws_frame fuzz_prepare_corpus
	$(SAN_RUN_ENV) /tmp/secchat_fuzz_json_validation $(FUZZ_JSON_CORPUS) -runs=$(FUZZ_RUNS) -max_len=4096 -artifact_prefix=$(FUZZ_ARTIFACTS)/json_validation/
	$(SAN_RUN_ENV) /tmp/secchat_fuzz_ws_frame $(FUZZ_WS_CORPUS) -runs=$(FUZZ_RUNS) -max_len=4096 -artifact_prefix=$(FUZZ_ARTIFACTS)/ws_frame/

fuzz_long: fuzz_json_validation fuzz_ws_frame fuzz_prepare_corpus
	$(SAN_RUN_ENV) /tmp/secchat_fuzz_json_validation $(FUZZ_JSON_CORPUS) -max_total_time=$(FUZZ_SECONDS) -max_len=4096 -artifact_prefix=$(FUZZ_ARTIFACTS)/json_validation/
	$(SAN_RUN_ENV) /tmp/secchat_fuzz_ws_frame $(FUZZ_WS_CORPUS) -max_total_time=$(FUZZ_SECONDS) -max_len=4096 -artifact_prefix=$(FUZZ_ARTIFACTS)/ws_frame/

cppcheck:
	cppcheck --enable=warning,performance,portability \
	    --std=c11 --inline-suppr --suppress=missingIncludeSystem \
	    -I. -Itransport -Iprotocol -Iinfra -Iservices -Irepository -Idomain \
	    $(filter-out cJSON.c,$(SRCS))

clean:
	rm -f $(OBJS) $(TARGET) /tmp/test_domain_unit /tmp/test_domain_unit_asan /tmp/secchat_fuzz_json_validation /tmp/secchat_fuzz_ws_frame
	rm -rf $(FUZZ_WORKDIR)
