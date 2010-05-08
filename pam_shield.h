/*
	pam_shield.h	WJ106
*/

#ifndef PAM_SHIELD_WJ106
#define PAM_SHIELD_WJ106	1

#include <netinet/in.h>

#define PAM_SHIELD_ADDR_IPV4		0
#define PAM_SHIELD_ADDR_IPV6		1

typedef struct {
	unsigned char addr_family;	/* PAM_SHIELD_ADDR_IPV4|PAM_SHIELD_ADDR_IPV6 */
	union {
		struct in_addr in;		/* IPv4 number */
		struct in6_addr in6;	/* IPv6 number */
		char any[1];			/* access to any */
	} ip;

	unsigned int max_entries;	/* number of timestamps */
	unsigned int count;			/* number of auth requests done */
	time_t trigger_active;		/* time the trigger was triggered (needed for expiration) */
	time_t timestamps[1];		/* sliding window of timestamps */
} _pam_shield_db_rec_t;


/*
	the IP list is used for making in-memory whitelists
	(they are not in the database, but in the config file)
*/
typedef struct ip_list_tag ip_list;

struct ip_list_tag {
	union {
		struct in_addr in;
		struct in6_addr in6;
		unsigned char any[1];
	} ip;

	union {
		struct in_addr in;
		struct in6_addr in6;
		unsigned char any[1];
	} mask;

	ip_list *prev, *next;
};

/* whitelisted hosntnames and network names */
typedef struct name_list_tag name_list;

struct name_list_tag {
	name_list *prev, *next;

	char name[1];
};

#endif	/* PAM_SHIELD_WJ106 */

/* EOB */
