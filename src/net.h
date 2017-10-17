/*****************************************************************************
* net.h - Network communications global header file.
*
* Copyright (c) 1998 Global Election Systems Inc.
*
* The authors hereby grant permission to use, copy, modify, distribute,
* and license this software and its documentation for any purpose, provided
* that existing copyright notices are retained in all copies and that this
* notice and the following disclaimer are included verbatim in any 
* distributions. No written agreement, license, or royalty fee is required
* for any of the authorized uses.
*
* THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS *AS IS* AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
* IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
******************************************************************************
* REVISION HISTORY
*
* 98-01-30 Guy Lancaster <glanca@gesn.com>, Global Election Systems Inc.
*	Original built from BSD network code.
******************************************************************************
* PURPOSE
*
*	This file contains all of the "global" data needed by the communications
* code.  This includes code collected from a number of public code sources as
* well as the code to interface it to our environment.
*****************************************************************************/
/*
 * ++Copyright++ 1985, 1989
 * -
 * Copyright (c) 1985, 1989
 *    The Regents of the University of California.  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 * 	This product includes software developed by the University of
 * 	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * -
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * -
 * --Copyright--
 */
/*
 * pppd.h - PPP daemon global declarations.
 *
 * Copyright (c) 1989 Carnegie Mellon University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Carnegie Mellon University.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * $Id: net.h,v 1.1.1.1 2000/10/16 04:36:12 guylancaster Exp $
 */
/*
 * ppp_defs.h - PPP definitions.
 *
 * Copyright (c) 1994 The Australian National University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied. The Australian National University
 * makes no representations about the suitability of this software for
 * any purpose.
 *
 * IN NO EVENT SHALL THE AUSTRALIAN NATIONAL UNIVERSITY BE LIABLE TO ANY
 * PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAVE BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 */

/*
 * Constants and structures defined by the internet system,
 * Per RFC 790, September 1981, and numerous additions.
 */

#ifndef NET_H
#define NET_H

/* This extends Borland C compiler definitions. */
#include <limits.h>


/*************************
*** PUBLIC DEFINITIONS ***
*************************/
#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef FALSE
#define FALSE 	0
#define TRUE	!0
#endif


/*
 * General return codes.
 */
#define RET_SUCCESS	0
#define RET_ERROR	!0

/*
 * Other general constants.
 */
#define KILOBYTE 1024L				/* Bytes in a kilobyte */


/************************
*** PUBLIC DATA TYPES ***
************************/
/* Compiler memory model types (Borland C). */
#define HUGE
#define FAR
#define NEAR
#define PUBLIC

/*
 *	A short int is the same size as an int for Turbo 'C' but the compiler
 *	does not use registers for short int but does for int 
 */
#define INT int
#define LONG long int
#define UINT unsigned short
#define USHORT unsigned short
#define ULONG unsigned long int
#define UCHAR unsigned char 
#define CHAR char


/* Type definitions for BSD code. */
typedef unsigned long u_int32_t;
typedef unsigned short u_int16_t;
typedef unsigned long u_long;
typedef unsigned short u_short;
typedef unsigned short u_int;
typedef unsigned char u_char;
typedef unsigned long n_long;		/* long as received from the net */
typedef unsigned short n_short;
typedef unsigned long n_time;
typedef unsigned long u_int32;

/*
 * Diagnostic statistics record structure.
 * This structure is designed to allow direct addressing of the statistics
 * counter (to minimize run time overhead) while also allowing automated 
 * display of the table.
 * This record should be put in a structure composed of only these records
 * with the last record having a null statistic name.  Then the statistics
 * can be printed automatically by treating the structure as an array.
 */
typedef struct {
	char	*fmtStr;	/* printf format string to display value. */
	u_long	val;		/* The statistics value. */
} DiagStat;


/***********************
*** PUBLIC FUNCTIONS ***
***********************/
#define hiword(x)		((USHORT)((x) >> 16))
#define	loword(x)		((USHORT)(x))
#define	hibyte(x)		(((x) >> 8) & 0xff)
#define	lobyte(x)		((x) & 0xff)
#define	hinibble(x)		(((x) >> 4) & 0xf)
#define	lonibble(x)		((x) & 0xf)
#define	dim(x)			(sizeof(x) / sizeof(x[0]))


/*
 * Segment handling helpers
 */
#define SEGMENT(p)      (int)((long)p >> 16)
#define OFFSET(p)       (int)((long)p & 0x0FFFF)
#define	MK_FP(seg,ofs)	((void FAR *) (((ULONG)(seg) << 16) | (UINT)(ofs)))
#define MK_LP(p)	    ((((ULONG)p & 0xffff0000) >> 12) + ((ULONG)p & 0x0000ffff))

/* 
 * Return the minimum and maximum of two values.  Not recommended for function
 * expressions.
 */
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MAX(a,b) ((a) > (b) ? (a) : (b))

/* XXX These should be the function call equivalents. */
#define max(a,b)	(((a) > (b)) ? (a) : (b))
#define min(a,b)	(((a) < (b)) ? (a) : (b))

/*
 * Borland library functions for which we cannot include the Borland header.
 */
INT rand(void);						/* random number function */

/* Allow function prototyping in BSD code. */
#undef __P
#define __P(c) c

/*
 * Interface types.
 */
/* Supported network interface types. */
typedef enum {
	IFT_UNSPEC = 0,				/* No interface */
	IFT_PPP						/* Point-to-Point Protocol */
} IfType;


/*
 * Address families.
 */
#define	AF_UNSPEC		0			/* unspecified */
#define	AF_LOCAL		1			/* local to host (pipes, portals) */
#define	AF_UNIX			AF_LOCAL	/* backward compatibility */
#define	AF_INET			2			/* internetwork: UDP, TCP, etc. */
#define	AF_IMPLINK		3			/* arpanet imp addresses */
#define	AF_PUP			4			/* pup protocols: e.g. BSP */
#define	AF_CHAOS		5			/* mit CHAOS protocols */
#define	AF_NS			6			/* XEROX NS protocols */
#define	AF_ISO			7			/* ISO protocols */
#define	AF_OSI			AF_ISO
#define	AF_ECMA			8			/* european computer manufacturers */
#define	AF_DATAKIT		9			/* datakit protocols */
#define	AF_CCITT		10			/* CCITT protocols, X.25 etc */
#define	AF_SNA			11			/* IBM SNA */
#define AF_DECnet		12			/* DECnet */
#define AF_DLI			13			/* DEC Direct data link interface */
#define AF_LAT			14			/* LAT */
#define	AF_HYLINK		15			/* NSC Hyperchannel */
#define	AF_APPLETALK	16			/* Apple Talk */
#define	AF_ROUTE		17			/* Internal Routing Protocol */
#define	AF_LINK			18			/* Link layer interface */
#define	pseudo_AF_XTP	19			/* eXpress Transfer Protocol (no AF) */
#define	AF_COIP			20			/* connection-oriented IP, aka ST II */
#define	AF_CNT			21			/* Computer Network Technology */
#define pseudo_AF_RTIP	22			/* Help Identify RTIP packets */
#define	AF_IPX			23			/* Novell Internet Protocol */
#define	AF_SIP			24			/* Simple Internet Protocol */
#define pseudo_AF_PIP	25			/* Help Identify PIP packets */
#define	AF_ISDN			26			/* Integrated Services Digital Network*/
#define	AF_E164			AF_ISDN		/* CCITT E.164 recommendation */
#define	pseudo_AF_KEY	27			/* Internal key-management function */
#define	AF_INET6		28			/* IPv6 */
#define	AF_NATM			29			/* native ATM access */
#define AF_PPP			30			/* PPP protocols */

#define	AF_MAX			31

/*
 * Protocols
 */
#define	IPPROTO_IP		0			/* dummy for IP */
#define	IPPROTO_ICMP	1			/* control message protocol */
#define	IPPROTO_IGMP	2			/* group mgmt protocol */
#define	IPPROTO_GGP		3			/* gateway^2 (deprecated) */
#define	IPPROTO_TCP		6			/* tcp */
#define	IPPROTO_EGP		8			/* exterior gateway protocol */
#define	IPPROTO_PUP		12			/* pup */
#define	IPPROTO_UDP		17			/* user datagram protocol */
#define	IPPROTO_IDP		22			/* xns idp */
#define	IPPROTO_TP		29 			/* tp-4 w/ class negotiation */
#define	IPPROTO_EON		80			/* ISO cnlp */
#define	IPPROTO_ENCAP	98			/* encapsulation header */

#define	IPPROTO_RAW		255			/* raw IP packet */
#define	IPPROTO_MAX		256

/*
 * The arguments to the ctlinput routine are
 *	(*protosw[].pr_ctlinput)(cmd, sa, arg);
 * where cmd is one of the commands below, sa is a pointer to a sockaddr,
 * and arg is an optional caddr_t argument used within a protocol family.
 */
#define	PRC_IFDOWN				0	/* interface transition */
#define	PRC_ROUTEDEAD			1	/* select new route if possible ??? */
#define	PRC_QUENCH2				3	/* DEC congestion bit says slow down */
#define	PRC_QUENCH				4	/* some one said to slow down */
#define	PRC_MSGSIZE				5	/* message size forced drop */
#define	PRC_HOSTDEAD			6	/* host appears to be down */
#define	PRC_HOSTUNREACH			7	/* deprecated (use PRC_UNREACH_HOST) */
#define	PRC_UNREACH_NET			8	/* no route to network */
#define	PRC_UNREACH_HOST		9	/* no route to host */
#define	PRC_UNREACH_PROTOCOL	10	/* dst says bad protocol */
#define	PRC_UNREACH_PORT		11	/* bad port # */
/* was	PRC_UNREACH_NEEDFRAG	12	   (use PRC_MSGSIZE) */
#define	PRC_UNREACH_SRCFAIL		13	/* source route failed */
#define	PRC_REDIRECT_NET		14	/* net routing redirect */
#define	PRC_REDIRECT_HOST		15	/* host routing redirect */
#define	PRC_REDIRECT_TOSNET		16	/* redirect for type of service & net */
#define	PRC_REDIRECT_TOSHOST	17	/* redirect for tos & host */
#define	PRC_TIMXCEED_INTRANS	18	/* packet lifetime expired in transit */
#define	PRC_TIMXCEED_REASS		19	/* lifetime expired on reass q */
#define	PRC_PARAMPROB			20	/* header incorrect */

#define	PRC_NCMDS				21

#define	PRC_IS_REDIRECT(cmd)	\
	((cmd) >= PRC_REDIRECT_NET && (cmd) <= PRC_REDIRECT_TOSHOST)


/*
 * The basic PPP frame.
 */
#define PPP_HDRLEN	4		/* octets for standard ppp header */
#define PPP_FCSLEN	2		/* octets for FCS */


/*
 * Significant octet values.
 */
#define	PPP_ALLSTATIONS	0xff	/* All-Stations broadcast address */
#define	PPP_UI			0x03	/* Unnumbered Information */
#define	PPP_FLAG		0x7e	/* Flag Sequence */
#define	PPP_ESCAPE		0x7d	/* Asynchronous Control Escape */
#define	PPP_TRANS		0x20	/* Asynchronous transparency modifier */

/*
 * Protocol field values.
 */
#define PPP_IP			0x21	/* Internet Protocol */
#define PPP_AT			0x29	/* AppleTalk Protocol */
#define	PPP_VJC_COMP	0x2d	/* VJ compressed TCP */
#define	PPP_VJC_UNCOMP	0x2f	/* VJ uncompressed TCP */
#define PPP_COMP		0xfd	/* compressed packet */
#define PPP_IPCP		0x8021	/* IP Control Protocol */
#define PPP_ATCP		0x8029	/* AppleTalk Control Protocol */
#define PPP_CCP			0x80fd	/* Compression Control Protocol */
#define PPP_LCP			0xc021	/* Link Control Protocol */
#define PPP_PAP			0xc023	/* Password Authentication Protocol */
#define PPP_LQR			0xc025	/* Link Quality Report protocol */
#define PPP_CHAP		0xc223	/* Cryptographic Handshake Auth. Protocol */
#define PPP_CBCP		0xc029	/* Callback Control Protocol */

/*
 * Values for FCS calculations.
 */
#define PPP_INITFCS	0xffff	/* Initial FCS value */
#define PPP_GOODFCS	0xf0b8	/* Good final FCS value */
#define PPP_FCS(fcs, c)	(((fcs) >> 8) ^ fcstab[((fcs) ^ (c)) & 0xff])

/*
 * Extended asyncmap - allows any character to be escaped.
 */
typedef u_char	ext_accm[32];

/*
 * What to do with network protocol (NP) packets.
 */
enum NPmode {
    NPMODE_PASS,		/* pass the packet through */
    NPMODE_DROP,		/* silently drop the packet */
    NPMODE_ERROR,		/* return an error */
    NPMODE_QUEUE		/* save it up for later. */
};

/*
 * Inline versions of get/put char/short/long.
 * Pointer is advanced; we assume that both arguments
 * are lvalues and will already be in registers.
 * cp MUST be u_char *.
 */
#define GETCHAR(c, cp) { \
	(c) = *(cp)++; \
}
#define PUTCHAR(c, cp) { \
	*(cp)++ = (u_char) (c); \
}


#define GETSHORT(s, cp) { \
	(s) = *(cp)++ << 8; \
	(s) |= *(cp)++; \
}
#define PUTSHORT(s, cp) { \
	*(cp)++ = (u_char) ((s) >> 8); \
	*(cp)++ = (u_char) (s); \
}

#define GETLONG(l, cp) { \
	(l) = *(cp)++ << 8; \
	(l) |= *(cp)++; (l) <<= 8; \
	(l) |= *(cp)++; (l) <<= 8; \
	(l) |= *(cp)++; \
}
#define PUTLONG(l, cp) { \
	*(cp)++ = (u_char) ((l) >> 24); \
	*(cp)++ = (u_char) ((l) >> 16); \
	*(cp)++ = (u_char) ((l) >> 8); \
	*(cp)++ = (u_char) (l); \
}


#define INCPTR(n, cp)	((cp) += (n))
#define DECPTR(n, cp)	((cp) -= (n))

#define BCMP(s0, s1, l)		memcmp((u_char *)(s0), (u_char *)(s1), (l))
#define BCOPY(s, d, l)		memcpy((d), (s), (l))
#define bcopy(s, d, l)		memcpy((d), (s), (l))
#define BZERO(s, n)			memset(s, 0, n)
#define bzero(s, n)			memset(s, 0, n)
#define EXIT(u)				panic("Net");

#define PRINTMSG(m, l)	{ m[l] = '\0'; trace(LOG_INFO, "Remote message: %Z", m); }

/*
 * MAKEHEADER - Add PPP Header fields to a packet.
 */
#define MAKEHEADER(p, t) { \
    PUTCHAR(PPP_ALLSTATIONS, p); \
    PUTCHAR(PPP_UI, p); \
    PUTSHORT(t, p); }

/*
 * Definitions of bits in internet address integers.
 * On subnets, the decomposition of addresses to host and net parts
 * is done according to subnet mask, not the masks here.
 */
#define	IN_CLASSA(i)		(((long)(i) & 0x80000000) == 0)
#define	IN_CLASSA_NET		0xff000000
#define	IN_CLASSA_NSHIFT	24
#define	IN_CLASSA_HOST		0x00ffffff
#define	IN_CLASSA_MAX		128

#define	IN_CLASSB(i)		(((long)(i) & 0xc0000000) == 0x80000000)
#define	IN_CLASSB_NET		0xffff0000
#define	IN_CLASSB_NSHIFT	16
#define	IN_CLASSB_HOST		0x0000ffff
#define	IN_CLASSB_MAX		65536

#define	IN_CLASSC(i)		(((long)(i) & 0xe0000000) == 0xc0000000)
#define	IN_CLASSC_NET		0xffffff00
#define	IN_CLASSC_NSHIFT	8
#define	IN_CLASSC_HOST		0x000000ff

#define	IN_CLASSD(i)		(((long)(i) & 0xf0000000) == 0xe0000000)
#define	IN_CLASSD_NET		0xf0000000	/* These ones aren't really */
#define	IN_CLASSD_NSHIFT	28		/* net and host fields, but */
#define	IN_CLASSD_HOST		0x0fffffff	/* routing needn't know.    */
#define	IN_MULTICAST(i)		IN_CLASSD(i)

#define	IN_EXPERIMENTAL(i)	(((long)(i) & 0xf0000000) == 0xf0000000)
#define	IN_BADCLASS(i)		(((long)(i) & 0xf0000000) == 0xf0000000)

#define	INADDR_ANY		(u_long)0x00000000
#define	INADDR_BROADCAST	(u_long)0xffffffff	/* must be masked */
#ifndef KERNEL
#define	INADDR_NONE		0xffffffff		/* -1 return */
#endif

#define	INADDR_UNSPEC_GROUP	(u_long)0xe0000000	/* 224.0.0.0 */
#define	INADDR_ALLHOSTS_GROUP	(u_long)0xe0000001	/* 224.0.0.1 */
#define	INADDR_MAX_LOCAL_GROUP	(u_long)0xe00000ff	/* 224.0.0.255 */

#define	IN_LOOPBACKNET		127			/* official! */

/*
 * Error return codes from gethostbyname() and gethostbyaddr()
 * (left in extern int h_errno).
 */

#define	HOST_NOT_FOUND	1 /* Authoritative Answer Host not found */
#define	TRY_AGAIN	2 /* Non-Authoritive Host not found, or SERVERFAIL */
#define	NO_RECOVERY	3 /* Non recoverable errors, FORMERR, REFUSED, NOTIMP */
#define	NO_DATA		4 /* Valid name, no data record of requested type */
#define	NO_ADDRESS	NO_DATA		/* no address, look for MX record *//*

/*
 * Definitions for IP type of service (ip_tos)
 */
#define	IPTOS_LOWDELAY		0x10
#define	IPTOS_THROUGHPUT	0x08
#define	IPTOS_RELIABILITY	0x04


/************************
*** PUBLIC DATA TYPES ***
************************/
/*
 * Structure used to store most network protocol addresses.
 */
typedef struct sockaddr {
	UCHAR	na_len;				/* total length */
	UCHAR	na_family;			/* address family */
	char	na_data[14];		/* actually longer; address value */
} NetAddr;

/*
 * Internet address (a structure for historical reasons)
 */
struct in_addr {
	u_long s_addr;
};

/*
 * Socket address, internet style.
 */
struct sockaddr_in {
	u_char	sin_len;
	u_char	sin_family;
	u_short	sin_port;
	struct	in_addr sin_addr;
	char	sin_zero[8];
};
#define ipAddr sin_addr.s_addr

/* TCP/IP Connection structure. */
typedef struct {
	struct sockaddr_in local;
	struct sockaddr_in remote;
} Connection;
#define localIPAddr local.sin_addr.s_addr
#define localPort local.sin_port
#define remoteIPAddr remote.sin_addr.s_addr
#define remotePort remote.sin_port


/*
 * The following struct gives the addresses of procedures to call
 * for a particular protocol.
 */
struct protent {
    u_short protocol;		/* PPP protocol number */
    /* Initialization procedure */
    void (*init) __P((int unit));
    /* Process a received packet */
    void (*input) __P((int unit, u_char *pkt, int len));
    /* Process a received protocol-reject */
    void (*protrej) __P((int unit));
    /* Lower layer has come up */
    void (*lowerup) __P((int unit));
    /* Lower layer has gone down */
    void (*lowerdown) __P((int unit));
    /* Open the protocol */
    void (*open) __P((int unit));
    /* Close the protocol */
    void (*close) __P((int unit, char *reason));
    /* Print a packet in readable form */
    int  (*printpkt) __P((u_char *pkt, int len,
			  void (*printer) __P((void *, char *, ...)),
			  void *arg));
    /* Process a received data packet */
    void (*datainput) __P((int unit, u_char *pkt, int len));
    int  enabled_flag;		/* 0 iff protocol is disabled */
    char *name;			/* Text name of protocol */
    /* Check requested options, assign defaults */
    void (*check_options) __P((void));
    /* Configure interface for demand-dial */
    int  (*demand_conf) __P((int unit));
    /* Say whether to bring up link for this pkt */
    int  (*active_pkt) __P((u_char *pkt, int len));
};

/*
 * The following structure records the time in seconds since
 * the last NP packet was sent or received.
 */
struct ppp_idle {
    u_short xmit_idle;		/* seconds since last NP packet sent */
    u_short recv_idle;		/* seconds since last NP packet received */
};

/*
 * Structures returned by network
 * data base library.  All addresses
 * are supplied in host order, and
 * returned in network order (suitable
 * for use in system calls).
 */
struct	hostent {
	char	*h_name;		/* official name of host */
	char	**h_aliases;	/* alias list */
	int		h_addrtype;		/* host address type */
	int		h_length;		/* length of address */
	char	**h_addr_list;	/* list of addresses from name server */
#define	h_addr	h_addr_list[0]	/* address, for backward compatiblity */
};

/*
 * Assumption here is that a network number
 * fits in 32 bits -- probably a poor one.
 */
struct	netent {
	char	*n_name;		/* official name of net */
	char	**n_aliases;	/* alias list */
	int		n_addrtype;		/* net address type */
	u_long	n_net;			/* network # */
};

struct	servent {
	char	*s_name;		/* official service name */
	char	**s_aliases;	/* alias list */
	int		s_port;			/* port # */
	char	*s_proto;		/* protocol to use */
};

struct	protoent {
	char	*p_name;		/* official protocol name */
	char	**p_aliases;	/* alias list */
	int		p_proto;	/* protocol # */
};

/*
 * Modified struct hostent from <netdb.h>
 *
 * "Structures returned by network data base library.  All addresses
 * are supplied in host order, and returned in network order (suitable
 * for use in system calls)."
 */

typedef struct	{
	char	*name;		/* official name of host */
	char	**domains;	/* domains it serves */
	char	**addrList;	/* list of addresses from name server */
} ServerInfo;

typedef struct	{
	char	*name;		/* official name of host */
	char	**aliases;	/* alias list */
	char	**addrList;	/* list of addresses from name server */
	int		addrType;	/* host address type */
	int		addrLen;	/* length of address */
	ServerInfo **servers;
} HostInfo;

typedef	char *		caddr_t;	/* core address */


/*****************************
*** PUBLIC DATA STRUCTURES ***
*****************************/
extern int	auth_required;		/* Peer is required to authenticate */
extern u_short idle_time_limit;	/* Shut down link if idle for this long */
extern int	maxconnect;			/* Maximum connect time (seconds) */
extern int	refuse_pap;			/* Don't wanna auth. ourselves with PAP */
extern int	refuse_chap;		/* Don't wanna auth. ourselves with CHAP */

extern char user[];				/* Username for PAP */
extern char	passwd[];			/* Password for PAP */
extern char	our_name[];			/* Our name for authentication purposes */
extern char	hostname[];			/* Our hostname */
extern char	remote_name[];		/* Peer's name for authentication */
extern int	explicit_remote;	/* remote_name specified with remotename opt */
extern int	usehostname;		/* Use hostname for our_name */

extern u_int32_t	netMask;	/* IP netmask to set on interface */
extern u_int32_t	localHost;	/* Our IP address in */

extern struct protent *protocols[];/* Table of pointers to supported protocols */


/***********************
*** PUBLIC FUNCTIONS ***
************************/
/*
 * netInit - Initialize the network communications subsystem.
 */
void netInit(void);

/*
 * Set the login user name and password for login and authentication
 *	purposes.  Using globals this way is rather hokey but until we
 *	fix some other things (like implementing a 2 step PPP open),
 *	this will do for now.
 */
void netSetLogin(const char *luser, const char *lpassword);

/* Convert a host long to a network long.  */
#define HTONL(n) (n = htonl(n))
extern u_long htonl (u_long __arg);

/* Convert a host short to a network short.  */
#define HTONS(n) (n = htons(n))
extern u_short htons (u_short __arg);

/* Convert a network long to a host long.  */
/* Note: We assume here that these are reversable. */
#define NTOHL(n) (n = htonl(n))
#define ntohl(n) htonl(n)

/* Convert a network short to a host short.  */
/* Note: We assume here that these are reversable. */
#define NTOHS(n) (n = htons(n))
#define ntohs(n) htons(n)

/*
 * print_string - print a readable representation of a string using
 * printer.
 */
void print_string(
	char *p,
	int len,
	void (*printer) __P((void *, char *, ...)),
	void *arg
);

void			endhostent __P((void));
void			endnetent __P((void));
void			endprotoent __P((void));
void			endservent __P((void));
struct hostent	*gethostbyaddr __P((const char *, int, int));
struct hostent	*gethostbyname __P((const char *));
struct hostent	*gethostent __P((void));
struct netent	*getnetbyaddr __P((long, int)); /* u_long? */
struct netent	*getnetbyname __P((const char *));
struct netent	*getnetent __P((void));
struct protoent	*getprotobyname __P((const char *));
struct protoent	*getprotobynumber __P((int));
struct protoent	*getprotoent __P((void));
struct servent	*getservbyname __P((const char *, const char *));
struct servent	*getservbyport __P((int, const char *));
struct servent	*getservent __P((void));
void			herror __P((const char *));
char			*hstrerror __P((int));
void			sethostent __P((int));
/* void			sethostfile __P((const char *)); */
void			setnetent __P((int));
void			setprotoent __P((int));
void			setservent __P((int));

u_int32_t GetMask __P((u_int32_t)); /* Get appropriate netmask for address */

/* in_canforward() - Dummy always succeeds. */
#define in_canforward(d) !0


#endif
