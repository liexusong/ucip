/* Configuration. */
#define NUM_PPP 1			/* Max PPP sessions. */
#define MAXPPPHDR 5			/* Max bytes of a PPP header with a flag. */
#define LOCALHOST "localhost"

/* Define the processor byte ordering for the network protocols. */
#define LITTLE_ENDIAN 1			/* Bytes swapped Intel style */
#define BIG_ENDIAN    2			/* Greatest to least significant ala Motorola */
#define BYTE_ORDER LITTLE_ENDIAN


/* Select modules to enable.  Ideally these would be set in the makefile but
 * we're limited by the command line length so you need to modify the settings
 * in this file.
 */
#define DEBUG_SUPPORT	 1		/* Set > 0 for debug monitor. */
#define STATS_SUPPORT	 1		/* Set > 0 for network statistics. */
#define PAP_SUPPORT		 1		/* Set > 0 for PAP. */
#define CHAP_SUPPORT	 0		/* Set > 0 for CHAP. */
#define MSCHAP_SUPPORT	 0		/* Set > 0 for MSCHAP (NOT FUNCTIONAL!) */
#define CBCP_SUPPORT	 0		/* Set > 0 for CBCP (NOT FUNCTIONAL!) */
#define CCP_SUPPORT		 0		/* Set > 0 for CCP (NOT FUNCTIONAL!) */
#define VJ_SUPPORT		 1		/* Set > 0 for VJ header compression. */
#define ECHO_SUPPORT	 0		/* Set > 0 for TCP echo service. */
 

#define OURADDR		0xAC100101	/* Local IP address - 0 to negotiate */
#define PEERADDR	0x00000000	/* Default peer IP address. */
#define LOOPADDR	0x7F000001	/* Loopback address (127.0.0.1) */ 
#define IPTTLDEFAULT 64			/* Default IP time-to-live. */

#define MAXWORDLEN	1024	/* max length of word in file (incl null) */
#define MAXARGS		1		/* max # args to a command */
#define MAXNAMELEN	256		/* max length of hostname or name for auth */
#define MAXSECRETLEN 256	/* max length of password or secret */
#define	IFNAMSIZ	16		/* Length of an interface name field. */

#define MAXIFHDR	MAXPPPHDR	/* Largest link level header. */

/*
 * Process stack sizes.
 */
#define OSMINSTACK	256
#define NETSTACK	OSMINSTACK + 512	/* Network goes deep. */

/*
 * Packet sizes
 *
 * Note - lcp shouldn't be allowed to negotiate stuff outside these
 *	  limits.  See lcp.h in the pppd directory.
 * (XXX - these constants should simply be shared by lcp.c instead
 *	  of living in lcp.h)
 */
#define	PPP_MTU		512		/* Default MTU (size of Info field) */
#ifdef XXX
#define PPP_MAXMTU	65535 - (PPP_HDRLEN + PPP_FCSLEN)
#else
#define PPP_MAXMTU	512	/* Largest MTU we allow */
#endif
#define PPP_MINMTU	64
#define PPP_MRU		512		/* default MRU = max length of info field */
#define PPP_MAXMRU	512		/* Largest MRU we allow */
#define PPP_MINMRU	128

#define PPP_ADDRESS(p)	(((u_char *)(p))[0])
#define PPP_CONTROL(p)	(((u_char *)(p))[1])
#define PPP_PROTOCOL(p)	((((u_char *)(p))[2] << 8) + ((u_char *)(p))[3])


/*
 * Operating system constants.
 */
#define TICKSPERSEC 1

/*
 * Operating system types.
 */
#define OS_EVENT long
#define MSPERTICK 1

/*
 * Operating system calls.
 */
long OSGetTime(void);
OS_EVENT *OSSemCreate(int);


#if STATS_SUPPORT > 0
#define STATS(cmd) cmd
#else
#define STATS(cmd)
#endif

