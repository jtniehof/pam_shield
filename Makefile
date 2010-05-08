#
#	pam_shield	WJ106
#

bindir=/usr/sbin
confdir=/etc/security
pamdir=/lib/security
crondir=/etc/cron.daily

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

.c.o:
	$(CC) $(CFLAGS) -c $<

all: .depend pam_shield.so shield-purge

include .depend

pam_shield.so: pam_shield.o
	$(CC) $(LFLAGS) -o pam_shield.so pam_shield.o $(PAM_LIB) $(GDBM_LIB) $(LIBS)

shield-purge: shield_purge.o
	$(CC) shield_purge.o -o shield-purge $(GDBM_LIB) $(LIBS)

clean:
	$(RM) core pam_shield.so pam_shield.o shield_purge.o shield-purge

mrproper: clean
	$(RM) db
	> .depend

dep depend .depend:
	$(CC) -M pam_shield.c shield_purge.c > .depend

install: all
	$(INSTALL) -s -o root -g root -m 644 pam_shield.so ${pamdir}
	$(INSTALL) -o root -g root -m 755 -T pam_shield.cron ${crondir}/pam-shield
	$(INSTALL) -o root -g root -m 755 shield-trigger.sh ${bindir}
	$(INSTALL) -s -o root -g root -m 755 shield-purge ${bindir}
	$(INSTALL) -o root -g root -m 644 shield.conf ${confdir}
	$(MKDIR) -p -m 700 /var/lib/pam_shield

uninstall:
	$(RM) ${pamdir}/pam_shield.so
	$(RM) ${crondir}/pam-shield
	$(RM) ${bindir}/shield-trigger.sh
	$(RM) ${bindir}/shield-purge
	$(RM) ${confdir}/shield.conf
	$(RM) -r /var/lib/pam_shield

# EOB
