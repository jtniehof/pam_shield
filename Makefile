#
#	pam_shield	WJ106
#

# for 32-bit systems:
pamdir = /lib/security
# for 64-bit systems:
#pamdir = /lib64/security

bindir = /usr/sbin
confdir = /etc/security
crondir = /etc/cron.daily
mandir = /usr/share/man/man8

CC = gcc
LD = ld
RM = rm -f
MKDIR = mkdir
INSTALL = install

CFLAGS = -Wall -Wstrict-prototypes -fPIC
LFLAGS = -shared -Xlinker -x
PAM_LIB = -lpam
GDBM_LIB = -lgdbm
LIBS =

.PHONY: all dep depend clean mrproper install uninstall

all: .depend pam_shield.so shield-purge

.depend dep depend: pam_shield.c shield_purge.c pam_shield_lib.c
	$(CC) -M pam_shield.c shield_purge.c pam_shield_lib.c > .depend

-include .depend

.c.o: .depend
	$(CC) $(CFLAGS) -c $<

pam_shield.so: pam_shield.o pam_shield_lib.o
	$(CC) $(LFLAGS) -o pam_shield.so pam_shield.o pam_shield_lib.o $(PAM_LIB) $(GDBM_LIB) $(LIBS)

shield-purge: shield_purge.o pam_shield_lib.o
	$(CC) shield_purge.o pam_shield_lib.o -o shield-purge $(GDBM_LIB) $(LIBS)

clean:
	$(RM) core pam_shield.so pam_shield.o shield_purge.o shield-purge pam_shield_lib.o

mrproper: clean
	$(RM) db
	$(RM) .depend

install: all
	$(INSTALL) -s -o root -g root -m 644 pam_shield.so ${pamdir}
	$(INSTALL) -o root -g root -m 644 man/shield-trigger.8.gz ${mandir}
	$(INSTALL) -o root -g root -m 644 man/shield-purge.8.gz ${mandir}
	$(INSTALL) -o root -g root -m 755 -T pam_shield.cron ${crondir}/pam-shield
	$(INSTALL) -o root -g root -m 755 shield-trigger ${bindir}
	$(INSTALL) -s -o root -g root -m 755 shield-purge ${bindir}
	if ! test -e ${confdir}/shield.conf; then \
	$(INSTALL) -o root -g root -m 644 shield.conf ${confdir} ; \
	fi
	$(MKDIR) -p -m 700 /var/lib/pam_shield

uninstall:
	$(RM) ${pamdir}/pam_shield.so
	$(RM) ${crondir}/pam-shield
	$(RM) ${bindir}/shield-trigger
	$(RM) ${bindir}/shield-purge
	$(RM) ${confdir}/shield.conf
	$(RM) -r /var/lib/pam_shield

# EOB
