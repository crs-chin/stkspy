
STKSPY_VERSION = 0.1

default:all

all:stkspy-$(STKSPY_VERSION)

CFLAGS += -DNDEBUG -O2 -DVERSION=\"$(STKSPY_VERSION)\"
LDFLAGS += -s

stkspy-$(STKSPY_VERSION):stkspy.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

install:stkspy-$(STKSPY_VERSION)
	install -D -m 755 destk.sh ~/bin/destk.sh
	install -D -m 755 stkspy-$(STKSPY_VERSION)  ~/bin/stkspy-$(STKSPY_VERSION)
	install -D -m 755 stkspy ~/bin/stkspy
	install -D -m 644 stkspy.clr  ~/.renderit/stkspy.clr

clean:
	rm stkspy-$(STKSPY_VERSION)
	rm stkspy.o

.phony:install clean
