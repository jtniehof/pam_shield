/*
	pam_shield_lib.c	WJ106

    pam_shield 0.9.6 WJ107
    Copyright (C) 2007-2012  Walter de Jong <walter@heiho.net>
    and Jonathan Niehof <jtniehof@gmail.com>

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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <pwd.h>
#include <time.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <gdbm.h>

#include "pam_shield_lib.h"

#pragma GCC visibility push(hidden)

int options = 0;
GDBM_FILE dbf;

char *conffile = NULL;
char *dbfile = NULL;
char *trigger_cmd = NULL;
char *removeip = NULL;

/* white lists of addresses */
ip_list *allow_ipv4_list = NULL;
ip_list *allow_ipv6_list = NULL;
name_list *allow_names = NULL;

int max_conns = DEFAULT_MAX_CONNS;
long interval = DEFAULT_INTERVAL;
long retention = DEFAULT_RETENTION;

time_t this_time;


ip_list *new_ip_list(void) {
ip_list *ip;

	if ((ip = (ip_list *)malloc(sizeof(ip_list))) == NULL)
		return NULL;

	memset(ip, 0, sizeof(ip_list));
	return ip;
}

void destroy_ip_list(ip_list *list) {
ip_list *p;

	while(list != NULL) {
		p = list;
		list = list->next;
		free(p);
	}
}

void add_ip_list(ip_list **root, ip_list *ip) {
	if (root == NULL || ip == NULL)
		return;

	if (options & OPT_DEBUG) {
		char addr[INET6_ADDRSTRLEN], mask[INET6_ADDRSTRLEN];

		if (*root == allow_ipv4_list)					/* (butt ugly check, just to get nice debug output) */
			logmsg(LOG_DEBUG, "allowing from %s/%s", inet_ntop(AF_INET, &ip->ip.in, addr, sizeof(addr)),
				inet_ntop(AF_INET, &ip->mask.in, mask, sizeof(mask)));
		else
			logmsg(LOG_DEBUG, "allowing from %s/%s", inet_ntop(AF_INET6, &ip->ip.in6, addr, sizeof(addr)),
				inet_ntop(AF_INET6, &ip->mask.in6, mask, sizeof(mask)));
	}
	ip->prev = ip->next = NULL;

	if (*root == NULL) {
		*root = ip;
		return;
	}
/* prepend it */
	(*root)->prev = ip;
	ip->next = *root;
	*root = ip;
}

/*
	try to match an IP number against the allow list
	returns 1 if it matches
*/
int match_ipv4_list(unsigned char *saddr) {
ip_list *ip;
int i, match;

	for(ip = allow_ipv4_list; ip != NULL; ip = ip->next) {
		match = 1;
		for(i = 0; i < sizeof(ip->ip.in.s_addr); i++) {
			if ((ip->ip.any[i] & ip->mask.any[i]) != (saddr[i] & ip->mask.any[i])) {
				match = 0;
				break;
			}
		}
		if (match) {
			char addr1[INET_ADDRSTRLEN], addr2[INET_ADDRSTRLEN], mask[INET_ADDRSTRLEN];

			logmsg(LOG_DEBUG, "whitelist match: %s %s/%s", inet_ntop(AF_INET, saddr, addr1, sizeof(addr1)),
				inet_ntop(AF_INET, &ip->ip.in, addr2, sizeof(addr2)),
				inet_ntop(AF_INET, &ip->mask.in, mask, sizeof(mask)));
			return 1;
		}
	}
	return 0;
}

int match_ipv6_list(unsigned char *saddr) {
ip_list *ip;
int i, match;

	for(ip = allow_ipv6_list; ip != NULL; ip = ip->next) {
		match = 1;
		for(i = 0; i < sizeof(ip->ip.in6.s6_addr); i++) {
			if ((ip->ip.any[i] & ip->mask.any[i]) != (saddr[i] & ip->mask.any[i])) {
				match = 0;
				break;
			}
		}
		if (match) {
			char addr1[INET6_ADDRSTRLEN], addr2[INET6_ADDRSTRLEN], mask[INET6_ADDRSTRLEN];

			logmsg(LOG_DEBUG, "whitelist match: %s %s/%s", inet_ntop(AF_INET6, saddr, addr1, sizeof(addr1)),
				inet_ntop(AF_INET6, &ip->ip.in6, addr2, sizeof(addr2)),
				inet_ntop(AF_INET6, &ip->mask.in6, mask, sizeof(mask)));
			return 1;
		}
	}
	return 0;
}

/*
	name_lists are hostnames and/or network names
*/
name_list *new_name_list(char *name) {
name_list *n;

	if (name == NULL || !*name)
		return NULL;

	if ((n = (name_list *)malloc(sizeof(name_list) + strlen(name))) == NULL)
		return NULL;

	memset(n, 0, sizeof(name_list));
	strcpy(n->name, name);
	return n;
}

void destroy_name_list(name_list *list) {
name_list *p;

	while(list != NULL) {
		p = list;
		list = list->next;
		free(p);
	}
}

void add_name_list(name_list **root, name_list *n) {
	if (root == NULL || n == NULL)
		return;

	logmsg(LOG_DEBUG, "allowing from %s", n->name);

	n->prev = n->next = NULL;

	if (*root == NULL) {
		*root = n;
		return;
	}
/* prepend it */
	(*root)->prev = n;
	n->next = *root;
	*root = n;
}


/*
	see if 'name' matches our whitelist
	return 1 if it does
*/
int match_name_list(char *name) {
name_list *n;

	if (name == NULL || !*name)
		return 0;

	for(n = allow_names; n != NULL; n = n->next) {
		if (n->name[0] == '.') {
			if ((strlen(name) > strlen(n->name)) && !strcasecmp(n->name, name + strlen(name) - strlen(n->name))) {
				logmsg(LOG_DEBUG, "whitelist match: host %s in domain %s", name, n->name);
				return 1;
			}
		} else {
			if (!strcasecmp(n->name, name)) {
				logmsg(LOG_DEBUG, "whitelist match: host %s", name);
				return 1;
			}
		}
	}
	return 0;
}


/*
	initialize variables
*/
int init_module(void) {
	this_time = time(NULL);

	conffile = strdup(DEFAULT_CONFFILE);
	dbfile = strdup(DEFAULT_DBFILE);
	trigger_cmd = strdup(DEFAULT_TRIGGER_CMD);

	if (conffile == NULL || dbfile == NULL || trigger_cmd == NULL) {
		logmsg(LOG_CRIT, "out of memory");
		return -1;
	}
	return 0;
}

void deinit_module(void) {
	if (conffile != NULL) {
		free(conffile);
		conffile = NULL;
	}
	if (dbfile != NULL) {
		free(dbfile);
		dbfile = NULL;
	}
	if (trigger_cmd != NULL) {
		free(trigger_cmd);
		trigger_cmd = NULL;
	}
	destroy_ip_list(allow_ipv4_list);
	allow_ipv4_list = NULL;

	destroy_ip_list(allow_ipv6_list);
	allow_ipv6_list = NULL;

	destroy_name_list(allow_names);
	allow_names = NULL;
}

/*
	strip leading and trailing whitespace from a string
*/
void strip(char *str) {
char *p;
int i;

	if (str == NULL || !*str)
		return;

	p = str;

	if (*p == ' ' || *p == '\t') {
		while(*p && (*p == ' ' || *p == '\t'))
			p++;

		memmove(str, p, strlen(p)+1);
	}
	i = strlen(str)-1;
	while(i >= 0 && (str[i] == ' ' || str[i] == '\t' || str[i] == '\r' || str[i] == '\n'))
		str[i--] = 0;
}


/*
	multipliers:
		1s	second
		1m	minute
		1h	hour
		1d	day
		1w	week
		1M	month
		1y	year

	default is 1
	returns 0 on error
*/
long get_multiplier(char *str) {
	if (str == NULL || !*str)
		return 1L;

	if (str[1])				/* we expect only a single character here */
		return 0L;

	switch(*str) {
		case 's':
			return 1L;

		case 'm':
			return 60L;

		case 'h':
			return 3600L;

		case 'd':
			return (3600L * 24L);

		case 'w':
			return (7L * 3600L * 24L);

		case 'M':
			return (30L * 3600L * 24L);

		case 'y':
		case 'Y':
			return (365L * 3600L * 24L);
	}
	return 0L;
}

/*
	generate bitmask from '/24' notation

	mask is struct in_addr.saddr, size is the size of the array
	(4 for IPv4, 16 for IPv6)
*/
void ip_bitmask(int bits, unsigned char *mask, int size) {
int i, num, rest;

	if (mask == NULL)
		return;

	memset(mask, 0, size);

	if (bits < 0)
		bits = 0;

	if (bits > size*8)
		bits = size*8;

	num = bits / 8;
	rest = bits % 8;

	for(i = 0; i < num; i++)
		mask[i] = 0xff;

	if (rest)
		mask[i++] = ~(0xff >> rest);

	while(i < size)
		mask[i++] = 0;
}

/*
	allow network/netmask, for both IPv4 and IPv6
	netmask can be in canonical or decimal notation
*/
int allow_ip(char *ipnum, int line_no) {
char *netmask;
ip_list *ip;
name_list *name;
int bits;

	if (ipnum == NULL || !*ipnum) {
		logmsg(LOG_ALERT, "%s:%d: missing argument to 'allow'", conffile, line_no);
		return -1;
	}
	if ((netmask = strchr(ipnum, '/')) != NULL) {
		*netmask = 0;
		netmask++;
		if (!*netmask) {
			logmsg(LOG_ALERT, "%s:%d: missing netmask, assuming it is a host", conffile, line_no);
			netmask = NULL;
		}
	}
	if ((ip = new_ip_list()) == NULL) {
		logmsg(LOG_ALERT, "%s:%d: out of memory adding 'allow' line", conffile, line_no);
		return -1;
	}
/* try network address as IPv4 */
	if (inet_pton(AF_INET, ipnum, &ip->ip.in) > 0) {
		if (netmask == NULL) {		/* no netmask given, treat as host */
			memset(&ip->mask.in.s_addr, 0xff, sizeof(ip->mask.in.s_addr));
			add_ip_list(&allow_ipv4_list, ip);
			return 0;
		}
/* netmask in '/24' like notation? */
		if (strspn(netmask, "0123456789") == strlen(netmask)) {
			bits = atoi(netmask);
			if (bits <= 0 || bits > 32) {
				logmsg(LOG_ALERT, "%s:%d: syntax error in netmask", conffile, line_no);
				destroy_ip_list(ip);
				return -1;
			}
			ip_bitmask(bits, (unsigned char *)&ip->mask.in.s_addr, sizeof(ip->mask.in.s_addr));

			add_ip_list(&allow_ipv4_list, ip);
			return 0;
		}
/* netmask in canonical notation? */
		if (inet_pton(AF_INET, netmask, &ip->mask.in) > 0) {
			add_ip_list(&allow_ipv4_list, ip);
			return 0;
		}
		logmsg(LOG_ALERT, "%s:%d: syntax error in netmask", conffile, line_no);
		destroy_ip_list(ip);
		return -1;
	}
/* try network address as IPv6 */
	if (inet_pton(AF_INET6, ipnum, &ip->ip.in6) > 0) {
		if (netmask == NULL) {		/* no netmask given, treat as host */
			memset(ip->mask.in6.s6_addr, 0xff, sizeof(ip->mask.in6.s6_addr));
			add_ip_list(&allow_ipv6_list, ip);
			return 0;
		}
/* netmask in '/24' like notation? */
		if (strspn(netmask, "0123456789") == strlen(netmask)) {
			bits = atoi(netmask);
			if (bits <= 0 || bits > 32) {
				logmsg(LOG_ALERT, "%s:%d: syntax error in netmask", conffile, line_no);
				destroy_ip_list(ip);
				return -1;
			}
			ip_bitmask(bits, (unsigned char *)ip->mask.in6.s6_addr, sizeof(ip->mask.in6.s6_addr));

			add_ip_list(&allow_ipv6_list, ip);
			return 0;
		}
/* netmask in canonical notation? */
		if (inet_pton(AF_INET6, netmask, &ip->mask.in6) > 0) {
			add_ip_list(&allow_ipv6_list, ip);
			return 0;
		}
		logmsg(LOG_ALERT, "%s:%d: syntax error in netmask", conffile, line_no);
		destroy_ip_list(ip);
		return -1;
	}
/*
	when we get here it's either a syntax error or a hostname or a network name
	with names, you can not specify a netmask
*/
	destroy_ip_list(ip);
	ip = NULL;

	if (netmask != NULL) {
		logmsg(LOG_ALERT, "%s:%d: syntax error in internet address", conffile, line_no);
		return -1;
	}
	if ((name = new_name_list(ipnum)) == NULL) {
		logmsg(LOG_ALERT, "%s:%d: out of memory while adding 'allow' line", conffile, line_no);
		return -1;
	}
	add_name_list(&allow_names, name);
	return 0;
}

/*
	read configuration file
*/
int read_config(void) {
FILE *f;
struct stat statbuf;
char buf[MAX_LINE], *p, *endp;
int line_no, err;
long multiplier;

	logmsg(LOG_DEBUG, "reading config file '%s'", conffile);

	if ((f = fopen(conffile, "r")) == NULL) {
		logmsg(LOG_ALERT, "failed to read config file '%s'", conffile);
		return -1;
	}
	line_no = 0;
	err = 0;

	while(fgets(buf, MAX_LINE, f) != NULL) {
		line_no++;

		strip(buf);
		if (!*buf || buf[0] == '#')
			continue;

/* keyword <space> value */

		p = buf;
		while(*p && *p != ' ' && *p != '\t')
			p++;

		if (!*p) {
			logmsg(LOG_ALERT, "%s:%d: syntax error", conffile, line_no);
			err--;
			continue;
		}
		*p = 0;
		p++;

		strip(buf);
		if (!*buf) {
			logmsg(LOG_ALERT, "%s:%d: syntax error", conffile, line_no);
			err--;
			continue;
		}
		strip(p);
		if (!*p) {
			logmsg(LOG_ALERT, "%s:%d: syntax error", conffile, line_no);
			err--;
			continue;
		}

/* buf is the key, p is the value */

		if (!strcmp(buf, "debug")) {
			if (!strcmp(p, "on") || !strcmp(p, "yes")) {
				options |= OPT_DEBUG;
				logmsg(LOG_DEBUG, "logging debug info");
				continue;
			}
			if (!strcmp(p, "off") || !strcmp(p, "no")) {
				logmsg(LOG_DEBUG, "ignoring config option 'debug %s' (overruled by PAM command line argument 'debug')", p);
				continue;
			}
			logmsg(LOG_ALERT, "%s:%d: unknown argument '%s' to 'debug'", conffile, line_no, p);
			continue;
		}
		if (!strcmp(buf, "block")) {
			if (!strcmp(p, "all-users")) {
				options |= OPT_BLOCK_ALL;
				continue;
			}
			if (!strcmp(p, "unknown-users")) {
				options &= ~OPT_BLOCK_ALL;
				continue;
			}
			logmsg(LOG_ALERT, "%s:%d: unknown argument '%s' to 'block'", conffile, line_no, p);
			err--;
			continue;
		}
		if (!strcmp(buf, "allow_missing_dns")) {
			if (!strcasecmp(p, "yes") || !strcasecmp(p, "allow") || !strcasecmp(p, "on")) {
				options |= OPT_MISSING_DNS;
				continue;
			}
			if (!strcasecmp(p, "no") || !strcasecmp(p, "deny") || !strcasecmp(p, "off")) {
				options &= ~OPT_MISSING_DNS;
				continue;
			}
			logmsg(LOG_ALERT, "%s:%d: unknown argument '%s' to 'allow_missing_dns'", conffile, line_no, p);
			err--;
			continue;
		}
		if (!strcmp(buf, "allow_missing_reverse")) {
			if (!strcasecmp(p, "yes") || !strcasecmp(p, "allow") || !strcasecmp(p, "on")) {
				options |= OPT_MISSING_REVERSE;
				continue;
			}
			if (!strcasecmp(p, "no") || !strcasecmp(p, "deny") || !strcasecmp(p, "off")) {
				options &= ~OPT_MISSING_REVERSE;
				continue;
			}
			logmsg(LOG_ALERT, "%s:%d: unknown argument '%s' to 'allow_missing_reverse'", conffile, line_no, p);
			err--;
			continue;
		}
		if (!strcmp(buf, "allow")) {
			if (allow_ip(p, line_no))
				err--;
			continue;
		}
		if (!strcmp(buf, "db")) {
			free(dbfile);
			if ((dbfile = strdup(p)) == NULL) {
				logmsg(LOG_CRIT, "out of memory");
				err--;
			}
			continue;
		}
		if (!strcmp(buf, "trigger_cmd")) {
			free(trigger_cmd);
			if ((trigger_cmd = strdup(p)) == NULL) {
				logmsg(LOG_CRIT, "out of memory");
				err--;
			}
			if (stat(trigger_cmd, &statbuf) == -1) {
				logmsg(LOG_ALERT, "%s:%d: command '%s' not found", conffile, line_no, trigger_cmd);
				err--;
			}
			continue;
		}
		if (!strcmp(buf, "max_conns")) {
			max_conns = (int)strtol(p, &endp, 10);
			if (*endp) {
				logmsg(LOG_ALERT, "%s:%d: syntax error", conffile, line_no);
				err--;
				max_conns = DEFAULT_MAX_CONNS;
			}
			continue;
		}
		if (!strcmp(buf, "interval")) {
			interval = (int)strtol(p, &endp, 10);
			if (!(multiplier = get_multiplier(endp))) {
				logmsg(LOG_ALERT, "%s:%d: syntax error", conffile, line_no);
				err--;
				interval = DEFAULT_INTERVAL;
			} else
				interval *= multiplier;
			continue;
		}
		if (!strcmp(buf, "retention")) {
			retention = (int)strtol(p, &endp, 10);
			if (!(multiplier = get_multiplier(endp))) {
				logmsg(LOG_ALERT, "%s:%d: syntax error", conffile, line_no);
				err--;
				retention = DEFAULT_RETENTION;
			} else
				retention *= multiplier;
			continue;
		}
		logmsg(LOG_ALERT, "%s:%d: unknown keyword '%s'", conffile, line_no, buf);
		err--;
	}
	fclose(f);

	logmsg(LOG_DEBUG, "done reading config file, %d errors", -err);

	return err;
}

/*
	print the IP number of a db_record
	return NULL on error, or buf on success
*/
const char *print_ip(_pam_shield_db_rec_t *record, char *buf, int buflen) {
	if (buf == NULL || buflen <= 1)
		return NULL;

	buflen--;
	if (!buflen) {
		*buf = 0;
		return buf;
	}
	if (record == NULL) {
		strncpy(buf, "(null)", buflen);
		buf[buflen] = 0;
		return buf;
	}
	switch(record->addr_family) {
		case PAM_SHIELD_ADDR_IPV4:
			return inet_ntop(AF_INET, &record->ip.in, buf, buflen);

		case PAM_SHIELD_ADDR_IPV6:
			return inet_ntop(AF_INET6, &record->ip.in6, buf, buflen);
	}
	return NULL;
}

/*
	run external command
*/
int run_trigger(char *cmd, _pam_shield_db_rec_t *record) {
char ipbuf[INET6_ADDRSTRLEN];
pid_t pid;

	if (cmd == NULL || record == NULL)
		return -1;

	if (print_ip(record, ipbuf, sizeof(ipbuf)) == NULL)
		return -1;

	logmsg(LOG_DEBUG, "running command '%s %s'", cmd, ipbuf);

	if (options & OPT_DRYRUN)
		return 0;

	pid = fork();
	if (pid == (pid_t)-1) {
		logmsg(LOG_CRIT, "can not fork, failed to run trigger");
		return -1;
	}
	if (!pid) {
		char *argv[4];

		argv[0] = trigger_cmd;
		argv[1] = cmd;
		argv[2] = ipbuf;
		argv[3] = NULL;

		execvp(argv[0], argv);

		logmsg(LOG_CRIT, "failed to execute command '%s %s %s'", trigger_cmd, cmd, ipbuf);
		exit(-1);
	} else {
		pid_t err;
		int status;

		while((err = waitpid(pid, &status, 0)) > 0);

		if (WEXITSTATUS(status) != 0)
			return -1;
	}
	return 0;
}

int expire_record(_pam_shield_db_rec_t *record) {
int updated;
char ipbuf[INET6_ADDRSTRLEN];

	if (record == NULL)
		return 0;

	updated = 0;
/*
	expire entries that are no longer in this interval (sliding window)
*/
	while(record->count > 0 && difftime(this_time, record->timestamps[0]) >= (double)interval) {
		memmove(record->timestamps, &record->timestamps[1], (record->max_entries-1)*sizeof(time_t));
		record->count--;
		updated++;
	}
	if (record->trigger_active) {
		if (difftime(this_time, record->trigger_active) >= (double)retention) {
/*
	expire old trigger, but only do this if the sliding window is clean
*/
			if (!record->count) {
				logmsg(LOG_DEBUG, "expiring old trigger for %s", print_ip(record, ipbuf, sizeof(ipbuf)));
				record->trigger_active = (time_t)0L;
				run_trigger("del", record);
				updated++;
			}
		} else {
			if (options & OPT_SYNC) {
				run_trigger("sync", record);
			}
		}
	}
	return updated;
}


/*
	gdbm has encountered a fatal error
*/
void fatal_func(const char *str) {
	logmsg(LOG_ERR, "gdbm encountered a fatal error : %s; resetting the database", str);

	gdbm_close(dbf);
	if ((dbf = gdbm_open(dbfile, 512, GDBM_NEWDB, (mode_t)0600, fatal_func)) == NULL)
		logmsg(LOG_ERR, "failed to create new gdbm file '%s' : %s", dbfile, gdbm_strerror(gdbm_errno));
}

#pragma GCC visibility pop
/* EOB */
