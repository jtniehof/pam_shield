/*
	pam_shield.c	WJ106

    pam_shield 0.9.4 WJ107
    Copyright (C) 2007,2010  Walter de Jong <walter@heiho.net>
    Copyright 2010 Jonathan Niehof <jtniehof@gmail.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
/*
	pam_shield is a PAM module that uses route/iptables to lock out script kiddies
	that probe your machine for open logins and/or easy guessable passwords.

	You can run this module with

	auth optional	pam_shield.so

	But just make sure it's not the only auth module you run..!
	This module does not do any authentication, it just monitors access.


	(btw, if you don't like my indentation, try setting tabsize to 4)
*/

#include "pam_shield.h"

#define PAM_SM_AUTH		1

#include <security/pam_modules.h>

#include "pam_shield_lib.c"


static void logmsg(int level, const char *fmt, ...) {
va_list varargs;

	if (level == LOG_DEBUG && !(options & OPT_DEBUG))
		return;

#ifdef LOG_AUTHPRIV
	openlog("PAM-shield", LOG_PID, LOG_AUTHPRIV);
#else
	openlog("PAM-shield", LOG_PID, LOG_AUTH);
#endif

	va_start(varargs, fmt);
	vsyslog(level, fmt, varargs);
	va_end(varargs);

	closelog();
}

/*
	Mind that argv[0] is an argument, not the name of the module
*/
static void get_options(int argc, char **argv) {
int i;

	for(i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "debug")) {
			options |= OPT_DEBUG;
			logmsg(LOG_DEBUG, "logging debug info");
			continue;
		}
		if (!strcmp(argv[i], "use_first_pass"))			/* Thorsten Kukuk sez all modules should accept this argument */
			continue;

		if (!strncmp(argv[i], "conf=", 5)) {
			conffile = argv[i] + 5;
			continue;
		}
		logmsg(LOG_ERR, "unknown argument '%s', ignored", argv[i]);
	}
}

static _pam_shield_db_rec_t *new_db_record(int window_size) {
_pam_shield_db_rec_t *record;
int size;

	if (window_size <= 0) {
		window_size = 1;
		size = sizeof(_pam_shield_db_rec_t);
	} else
		size = sizeof(_pam_shield_db_rec_t) + (window_size-1) * sizeof(time_t);

	if ((record = (_pam_shield_db_rec_t *)malloc(size)) == NULL) {
		logmsg(LOG_CRIT, "new_db_record(): out of memory allocating %d bytes", size);
		return NULL;
	}
	memset(record, 0, size);
	record->max_entries = window_size;
	return record;
}

static void destroy_db_record(_pam_shield_db_rec_t *record) {
	if (record != NULL)
		free(record);
}

/*
	get remote IPs for the rhost

	the return value must be freed with freeaddrinfo()
*/
static struct addrinfo *get_addr_info(char *rhost) {
struct addrinfo hints, *res;
int err;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((err = getaddrinfo(rhost, NULL, &hints, &res)) != 0) {
		logmsg(LOG_ERR, "%s: %s\n", rhost, gai_strerror(err));
		return NULL;
	}
	return res;
}

/*
	the authenticate function always returns PAM_IGNORE, because this
	module does not really authenticate
*/
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
char *user, *rhost;
struct passwd *pwd;
unsigned int retry_count;

	if (init_module())
		return PAM_IGNORE;

	get_options(argc, (char **)argv);
	logmsg(LOG_DEBUG, "this is version " PAM_SHIELD_VERSION);

/*
	read_config() may fail (due to syntax errors, etc.), try to make the best of it
	by continuing anyway
*/
	read_config();

/* get the username */
	if (pam_get_item(pamh, PAM_USER, (const void **)(void *)&user) != PAM_SUCCESS)
		user = NULL;

	if (user != NULL && !*user)
		user = NULL;

	logmsg(LOG_DEBUG, "user %s", (user == NULL) ? "(unknown)" : user);

/* get the remotehost address */
	if (pam_get_item(pamh, PAM_RHOST, (const void **)(void *)&rhost) != PAM_SUCCESS)
		rhost = NULL;

	if (rhost != NULL && !*rhost)
		rhost = NULL;

	logmsg(LOG_DEBUG, "remotehost %s", (rhost == NULL) ? "(unknown)" : rhost);

/*
	if rhost is completely numeric, then it has no DNS entry
*/
	if (strspn(rhost, "0123456789.") == strlen(rhost)
		|| strspn(rhost, "0123456789:abcdefABCDEF") == strlen(rhost)) {
		if (options & OPT_MISSING_DNS)
			logmsg(LOG_DEBUG, "missing DNS entry for %s (allowed)", rhost);
		else {
			logmsg(LOG_DEBUG, "missing DNS entry for %s (denied)", rhost);
/*
	FIXME
	The IPaddress of the attacker is not getting blocked ever (!) in this case
	because we're returning right now
*/
			deinit_module();
			return PAM_AUTH_ERR;
		}
	} else {
/*
	see if this rhost is whitelisted
*/
		if (match_name_list(rhost)) {
			deinit_module();
			return PAM_IGNORE;
		}
	}

/* if not blocking all and the user is known, let go */
	if (!(options & OPT_BLOCK_ALL) && user != NULL && (pwd = getpwnam(user)) != NULL) {
		logmsg(LOG_DEBUG, "ignoring known user %s", user);
		deinit_module();
		return PAM_IGNORE;
	}
	if (rhost != NULL) {
		struct addrinfo *addr_info, *addr_p;
		unsigned char addr_family;
		char ipbuf[INET6_ADDRSTRLEN], *saddr;
		_pam_shield_db_rec_t *record;
		datum key, data;
		int whitelisted;

		if ((addr_info = get_addr_info(rhost)) == NULL) {		/* missing reverse DNS entry */
			deinit_module();

			if (options & OPT_MISSING_REVERSE)
				logmsg(LOG_DEBUG, "missing reverse DNS entry for %s (allowed)", rhost);
			else {
				logmsg(LOG_DEBUG, "missing reverse DNS entry for %s (denied)", rhost);
/*
	FIXME
	The IPaddress of the attacker is not getting blocked ever (!) in this case
	because we're returning right now
*/
				deinit_module();
				return PAM_AUTH_ERR;
			}
		}
/* for every address that this host is known for, check for whitelist entry */
		for(addr_p = addr_info; addr_p != NULL; addr_p = addr_p->ai_next) {
			whitelisted = 0;
			switch(addr_p->ai_family) {
				case PF_INET:
					saddr = (char *)&((struct sockaddr_in *)(addr_p->ai_addr))->sin_addr.s_addr;

					if (match_ipv4_list((unsigned char *)saddr)) {
						logmsg(LOG_DEBUG, "remoteip %s (whitelisted)", inet_ntop(AF_INET, (char *)&((struct sockaddr_in *)(addr_p->ai_addr))->sin_addr, ipbuf, sizeof(ipbuf)));
						whitelisted = 1;
					} else
						logmsg(LOG_DEBUG, "remoteip %s", inet_ntop(AF_INET, (char *)&((struct sockaddr_in *)(addr_p->ai_addr))->sin_addr, ipbuf, sizeof(ipbuf)));
					break;
				
				case PF_INET6:
					saddr = (char *)&((struct sockaddr_in6 *)(addr_p->ai_addr))->sin6_addr.s6_addr;

					if (match_ipv6_list((unsigned char *)saddr)) {
						logmsg(LOG_DEBUG, "remoteip %s (whitelisted)", inet_ntop(AF_INET6, (char *)&((struct sockaddr_in6 *)(addr_p->ai_addr))->sin6_addr, ipbuf, sizeof(ipbuf)));
						whitelisted = 1;
					} else
						logmsg(LOG_DEBUG, "remoteip %s", inet_ntop(AF_INET6, (char *)&((struct sockaddr_in6 *)(addr_p->ai_addr))->sin6_addr, ipbuf, sizeof(ipbuf)));
					break;

				default:
					logmsg(LOG_DEBUG, "remoteip unknown (not IP)");

					freeaddrinfo(addr_info);
					deinit_module();
					return PAM_IGNORE;
			}
/* host is whitelisted by an allow line in the config file, so exit */
			if (whitelisted) {
				freeaddrinfo(addr_info);
				deinit_module();
				return PAM_IGNORE;
			}
		}
/* open the database */
		retry_count=0;
		while ((dbf = gdbm_open(dbfile, 512, GDBM_WRCREAT, (mode_t)0600, fatal_func)) == NULL) {
			if (gdbm_errno != GDBM_CANT_BE_WRITER || retry_count>500) {
				logmsg(LOG_ERR, "failed to open gdbm file '%s' : %s", dbfile,
				       gdbm_strerror(gdbm_errno));
				freeaddrinfo(addr_info);
				deinit_module();
				return PAM_IGNORE;
			}
			logmsg(LOG_DEBUG,"waiting to open db, try %d",retry_count);
			usleep(1000);
			retry_count++;
		}
/* for every address that this host is known for, check the database */
		for(addr_p = addr_info; addr_p != NULL; addr_p = addr_p->ai_next) {
			whitelisted = 0;
			switch(addr_p->ai_family) {
				case PF_INET:
					addr_family = PAM_SHIELD_ADDR_IPV4;
					key.dptr = saddr = (char *)&((struct sockaddr_in *)(addr_p->ai_addr))->sin_addr.s_addr;
					key.dsize = sizeof(struct in_addr);
					break;

				case PF_INET6:
					addr_family = PAM_SHIELD_ADDR_IPV6;
					key.dptr = saddr = (char *)&((struct sockaddr_in6 *)(addr_p->ai_addr))->sin6_addr.s6_addr;
					key.dsize = sizeof(struct in6_addr);
					break;

				default:
					addr_family = -1;
					key.dptr = saddr = NULL;
					key.dsize = 0;
			}
			if (key.dptr == NULL)
				continue;

			data = gdbm_fetch(dbf, key);			/* get db record */
			if (data.dptr != NULL) {
				record = (_pam_shield_db_rec_t *)data.dptr;
/*
	Although this code does some expiration, it only does so for "this ip";
	it is still necessary to run an external database cleanup process every
	now and then (eg, from cron.daily)
*/
				expire_record(record);

				if (record->count >= record->max_entries) {		/* shift, so we always log the most recent time */
					memmove(record->timestamps, &record->timestamps[1], (record->max_entries-1)*sizeof(time_t));
					record->count--;
				}
				record->timestamps[record->count++] = this_time;

				logmsg(LOG_DEBUG, "%u times from %s", record->count, rhost);
/*
	too many in the interval, so trigger

	trigger "add" is subject to a race, so try to be smart about it
	and do not add the same block within 20 seconds
*/
				if (record->count >= max_conns && this_time - record->trigger_active > 20
					&& !run_trigger("add", record))
					record->trigger_active = this_time;
			} else {
				if ((record = new_db_record(max_conns)) != NULL) {
					record->addr_family = addr_family;
					memcpy(record->ip.any, saddr, key.dsize);
					record->timestamps[record->count++] = this_time;

					logmsg(LOG_DEBUG, "putting new record in db");

					if (max_conns <= 1) {		/* (maybe) stupid, but possible */
						record->trigger_active = this_time;
						run_trigger("add", record);
					}
				}
			}
			if (record != NULL) {
				data.dptr = (char *)record;
				data.dsize = sizeof(_pam_shield_db_rec_t) + (record->max_entries-1)*sizeof(time_t);

/* key.dptr and key.dsize are still set to saddr and addr_size */

				if (gdbm_store(dbf, key, data, GDBM_REPLACE))
					logmsg(LOG_ERR, "failed to write db record");
			}
			destroy_db_record(record);
		}
		freeaddrinfo(addr_info);
		gdbm_close(dbf);
	}
	deinit_module();
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

/* EOB */
