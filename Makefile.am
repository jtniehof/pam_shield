
AUTOMAKE_OPTIONS   = foreign subdir-objects
moduledir          = @PAM_MODDIR@
module_LTLIBRARIES = pam_shield.la
sbin_PROGRAMS      = shield-purge
#sbin_SCRIPTS       = shield-trigger.sh shield-trigger-iptables.sh
securitydir        = ${sysconfdir}/security
security_DATA      = shield.conf

AM_CFLAGS = -D_LARGEFILE_SOURCE=1 -D_LARGE_FILES -D_FILE_OFFSET_BITS=64 \
            -D_REENTRANT -Wall -Wmissing-declarations -Wmissing-prototypes \
            -Wredundant-decls -Wshadow -Wstrict-prototypes -Winline -pipe

pam_shield_la_LDFLAGS = -module -avoid-version
pam_shield_la_LIBADD  = -lgdbm -lpam
pam_shield_la_SOURCES = pam_shield.c pam_shield_lib.c
shield_purge_LDFLAGS  = -lgdbm
shield_purge_SOURCES = shield_purge.c pam_shield_lib.c
shield_purge_CFLAGS = $(AM_CFLAGS)

install-exec-hook:
	rm -f "${DESTDIR}${moduledir}/pam_shield.la";
	${INSTALL} -dm0755 "${DESTDIR}${sbindir}";
#	ln -s shield-trigger.sh "${DESTDIR}${sbindir}/pam_shield-trigger";
