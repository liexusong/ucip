/*****************************************************************************
* neticmp.c - Network Internet Control Message Protocol program file.
*
* Copyright (c) 1997 by Global Election Systems Inc.  All rights reserved.
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
* 98-01-22 Guy Lancaster <lancasterg@acm.org>, Global Election Systems Inc.
*	Extracted from BSD's ip_icmp.c and icmp_var.h.
*****************************************************************************/
/*
 * Copyright (c) 1982, 1986, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
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
 *
 *	@(#)ip_icmp.c	8.2 (Berkeley) 1/4/94
 *
 *	@(#)icmp_var.h	8.1 (Berkeley) 6/10/93
 */
/*
 * ICMP routines: error generation, receive packet processing, and
 * routines to turnaround packets back to the originator, and
 * host table maintenance routines.
 */



#include "netconf.h"
#include <string.h>
#include <time.h>
#include "net.h"
#include "netbuf.h"
#include "netip.h"
#include "netiphdr.h"
#include "neticmp.h"

#include <stdio.h>
#include "netdebug.h"


/*************************/
/*** LOCAL DEFINITIONS ***/
/*************************/
/*
 * Names for ICMP sysctl objects
 */
#define	ICMPCTL_MASKREPL	1	/* allow replies to netmask requests */
#define ICMPCTL_MAXID		2

#define ICMPCTL_NAMES { \
	{ 0, 0 }, \
	{ "maskrepl", CTLTYPE_INT }, \
}

                                                                    
/************************/
/*** LOCAL DATA TYPES ***/
/************************/


/***********************************/
/*** LOCAL FUNCTION DECLARATIONS ***/
/***********************************/
static void icmpReflect(NBuf *nb);
static void icmpSend(
	register NBuf *nb,
	NBuf *opts
);
static u_long iptime(void);


/******************************/
/*** PUBLIC DATA STRUCTURES ***/
/******************************/
IcmpStats icmpStats;


/***********************************/
/*** PUBLIC FUNCTION DEFINITIONS ***/
/***********************************/
void icmpInit(void)
{
	memset(&icmpStats, 0, sizeof(icmpStats));
}


/*
 * Generate an error packet of type error
 * in response to bad packet ip.
 */
void icmp_error(
	NBuf *nb,
	int type, 
	int code,
	n_long dest
)
{
	register IPHdr *oip = nBUFTOPTR(nb, IPHdr *), *nip;
	register unsigned oiplen = oip->ip_hl << 2;
	register IcmpHdr *icp;
	register NBuf *n0;
	unsigned icmplen;

	ICMPDEBUG((LOG_INFO, "icmp_error(%x, %d, %d)\n", oip, type, code));
	
	if (type != ICMP_REDIRECT)
		icmpStats.icps_error++;
	/*
	 * Don't send error if not the first fragment of message.
	 * Don't error if the old packet protocol was ICMP
	 * error message, only known informational types.
	 */
	if (oip->ip_off &~ (IP_MF|IP_DF))
		goto freeit;
	if (oip->ip_p == IPPROTO_ICMP && type != ICMP_REDIRECT &&
			nb->len >= oiplen + ICMP_MINLEN &&
			!ICMP_INFOTYPE(((IcmpHdr *)((caddr_t)oip + oiplen))->icmp_type)) {
		icmpStats.icps_oldicmp++;
		goto freeit;
	}
	/* Don't send error in response to a multicast or broadcast packet */
	/* XXX */
	/*
	 * First, formulate icmp message
	 */
	nGET(n0);
	if (n0 == NULL)
		goto freeit;
	icmplen = oiplen + min(8, oip->ip_len);
	n0->len = n0->chainLen = icmplen + ICMP_MINLEN;
	nALIGN(n0, n0->len);
	icp = nBUFTOPTR(n0, IcmpHdr *);
	if ((u_int)type > ICMP_MAXTYPE)
		panic("icmp_error");
	icmpStats.icps_outhist[type]++;
	icp->icmp_type = type;
	if (type == ICMP_REDIRECT)
		icp->icmp_gwaddr.s_addr = dest;
	else {
		icp->icmp_void = 0;
		/* 
		 * The following assignments assume an overlay with the
		 * zeroed icmp_void field.
		 */
		if (type == ICMP_PARAMPROB) {
			icp->icmp_pptr = code;
			code = 0;
		} 
	}

	icp->icmp_code = code;
	bcopy((caddr_t)oip, (caddr_t)&icp->icmp_ip, icmplen);
	nip = &icp->icmp_ip;
	nip->ip_len = htons((u_short)(nip->ip_len + oiplen));

	/*
	 * Now, copy old ip header (without options)
	 * in front of icmp message.
	 */
	nPREPEND(n0, oip, sizeof(IPHdr));
	nip = nBUFTOPTR(n0, IPHdr *);
	nip->ip_len = n0->len;
	nip->ip_hl = sizeof(IPHdr) >> 2;
	nip->ip_p = IPPROTO_ICMP;
	nip->ip_tos = 0;
	icmpReflect(n0);

freeit:
	nFreeChain(nb);
}

static struct sockaddr_in icmpsrc = { sizeof (struct sockaddr_in), AF_INET };
struct sockaddr_in icmpmask = { 8, 0 };

/*
 * Process a received ICMP message.
 */
void icmpInput(NBuf *inBuf, int ipHdrLen)
{
	register IcmpHdr *icp;
	register IPHdr *ip = nBUFTOPTR(inBuf, IPHdr *);
	int icmplen = ip->ip_len - ipHdrLen;
	register int i;
	int code;
	extern u_char ip_protox[];

	ICMPDEBUG((LOG_INFO, "icmp_input from %s to %s, len %d\n",
			ip_ntoa(ip->ip_src.s_addr), 
			ip_ntoa2(ip->ip_dst.s_addr),
			icmplen));
			
	/*
	 * Locate icmp structure in nBuf, and check
	 * that not corrupted and of at least minimum length.
	 */
	if (icmplen < ICMP_MINLEN) {
		icmpStats.icps_tooshort++;
		goto freeit;
	}
	i = ipHdrLen + min(icmplen, ICMP_ADVLENMIN);
	if (inBuf->len < i && (inBuf = nPullup(inBuf, i)) == NULL)  {
		icmpStats.icps_tooshort++;
		return;
	}
	ip = nBUFTOPTR(inBuf, IPHdr *);
	icp = (IcmpHdr *)(nBUFTOPTR(inBuf, char *) + ipHdrLen);
	if (inChkSum(inBuf, icmplen, ipHdrLen)) {
		icmpStats.icps_checksum++;
		goto freeit;
	}

	/*
	 * Message type specific processing.
	 */
	ICMPDEBUG((LOG_INFO, "icmp_input, type %d code %d\n", icp->icmp_type,
		    icp->icmp_code));
	if (icp->icmp_type > ICMP_MAXTYPE)
		goto raw;
	icmpStats.icps_inhist[icp->icmp_type]++;
	code = icp->icmp_code;
	switch (icp->icmp_type) {

	case ICMP_UNREACH:
		switch (code) {
			case ICMP_UNREACH_NET:
			case ICMP_UNREACH_HOST:
			case ICMP_UNREACH_PROTOCOL:
			case ICMP_UNREACH_PORT:
			case ICMP_UNREACH_SRCFAIL:
				code += PRC_UNREACH_NET;
				break;

			case ICMP_UNREACH_NEEDFRAG:
				code = PRC_MSGSIZE;
				break;
				
			case ICMP_UNREACH_NET_UNKNOWN:
			case ICMP_UNREACH_NET_PROHIB:
			case ICMP_UNREACH_TOSNET:
				code = PRC_UNREACH_NET;
				break;

			case ICMP_UNREACH_HOST_UNKNOWN:
			case ICMP_UNREACH_ISOLATED:
			case ICMP_UNREACH_HOST_PROHIB:
			case ICMP_UNREACH_TOSHOST:
				code = PRC_UNREACH_HOST;
				break;

			default:
				goto badcode;
		}
		goto deliver;

	case ICMP_TIMXCEED:
		if (code > 1)
			goto badcode;
		code += PRC_TIMXCEED_INTRANS;
		goto deliver;

	case ICMP_PARAMPROB:
		if (code > 1)
			goto badcode;
		code = PRC_PARAMPROB;
		goto deliver;

	case ICMP_SOURCEQUENCH:
		if (code)
			goto badcode;
		code = PRC_QUENCH;
	deliver:
		/*
		 * Problem with datagram; advise higher level routines.
		 */
		if (icmplen < ICMP_ADVLENMIN || icmplen < ICMP_ADVLEN(icp) ||
				icp->icmp_ip.ip_hl < (sizeof(IPHdr) >> 2)) {
			icmpStats.icps_badlen++;
			goto freeit;
		}
		NTOHS(icp->icmp_ip.ip_len);
		ICMPDEBUG((LOG_INFO, "icmp_input: deliver to protocol %d\n", icp->icmp_ip.ip_p));
		icmpsrc.sin_addr = icp->icmp_ip.ip_dst;
#ifdef XXX  /* We need a method here of selecting input handlers... */
		if (ctlfunc = inetsw[ip_protox[icp->icmp_ip.ip_p]].pr_ctlinput)
			(*ctlfunc)(code, (struct sockaddr *)&icmpsrc,
			    &icp->icmp_ip);
#endif
		
		break;

	badcode:
		icmpStats.icps_badcode++;
		break;

	case ICMP_ECHO:
		icp->icmp_type = ICMP_ECHOREPLY;
		goto reflect;

	case ICMP_TSTAMP:
		if (icmplen < ICMP_TSLEN) {
			icmpStats.icps_badlen++;
			break;
		}
		icp->icmp_type = ICMP_TSTAMPREPLY;
		icp->icmp_rtime = iptime();
		icp->icmp_ttime = icp->icmp_rtime;	/* bogus, do later! */
		goto reflect;
		
	case ICMP_MASKREQ:
#ifdef XXX /* Not currently supported... */
#define	satosin(sa)	((struct sockaddr_in *)(sa))
		if (icmpmaskrepl == 0)
			break;
		/*
		 * We are not able to respond with all ones broadcast
		 * unless we receive it over a point-to-point interface.
		 */
		if (icmplen < ICMP_MASKLEN)
			break;
		switch (ip->ip_dst.s_addr) {

		case INADDR_BROADCAST:
		case INADDR_ANY:
			icmpdst.sin_addr = ip->ip_src;
			break;

		default:
			icmpdst.sin_addr = ip->ip_dst;
		}
		ia = (struct in_ifaddr *)ifaof_ifpforaddr(
			    (struct sockaddr *)&icmpdst, m->m_pkthdr.rcvif);
		if (ia == 0)
			break;
		icp->icmp_type = ICMP_MASKREPLY;
		icp->icmp_mask = ia->ia_sockmask.sin_addr.s_addr;
		if (ip->ip_src.s_addr == 0) {
			if (ia->ia_ifp->if_flags & IFF_BROADCAST)
			    ip->ip_src = satosin(&ia->ia_broadaddr)->sin_addr;
			else if (ia->ia_ifp->if_flags & IFF_POINTOPOINT)
			    ip->ip_src = satosin(&ia->ia_dstaddr)->sin_addr;
		}
#else
		break;
#endif
reflect:
#ifdef XXX
	/* XXX No longer! */
		ip->ip_len += ipHdrLen;	/* since ip_input deducts this */
#endif
		icmpStats.icps_reflect++;
		icmpStats.icps_outhist[icp->icmp_type]++;
		icmpReflect(inBuf);
		return;

	case ICMP_REDIRECT:
#ifdef XXX /* Not currently supported... */
		if (code > 3)
			goto badcode;
		if (icmplen < ICMP_ADVLENMIN || icmplen < ICMP_ADVLEN(icp) ||
		    icp->icmp_ip.ip_hl < (sizeof(IPHdr) >> 2)) {
			icmpStats.icps_badlen++;
			break;
		}
		/*
		 * Short circuit routing redirects to force
		 * immediate change in the kernel's routing
		 * tables.  The message is also handed to anyone
		 * listening on a raw socket (e.g. the routing
		 * daemon for use in updating its tables).
		 */
		icmpgw.sin_addr = ip->ip_src;
		icmpdst.sin_addr = icp->icmp_gwaddr;
#ifdef	ICMPPRINTFS
		if (icmpprintfs)
			printf("redirect dst %x to %x\n", icp->icmp_ip.ip_dst,
				icp->icmp_gwaddr);
#endif
		icmpsrc.sin_addr = icp->icmp_ip.ip_dst;
		rtredirect((struct sockaddr *)&icmpsrc,
		  (struct sockaddr *)&icmpdst,
		  (struct sockaddr *)0, RTF_GATEWAY | RTF_HOST,
		  (struct sockaddr *)&icmpgw, (struct rtentry **)0);
		pfctlinput(PRC_REDIRECT_HOST, (struct sockaddr *)&icmpsrc);
#endif
		break;

	/*
	 * No kernel processing for the following;
	 * just fall through to send to raw listener.
	 */
	case ICMP_ECHOREPLY:
	case ICMP_ROUTERADVERT:
	case ICMP_ROUTERSOLICIT:
	case ICMP_TSTAMPREPLY:
	case ICMP_IREQREPLY:
	case ICMP_MASKREPLY:
	default:
		break;
	}

raw:
	ripInput(inBuf);
	return;

freeit:
	nFreeChain(inBuf);
}


/**********************************/
/*** LOCAL FUNCTION DEFINITIONS ***/
/**********************************/
/*
 * Reflect the ip packet back to the source
 */
static void icmpReflect(NBuf *nb)
{
	register IPHdr *ip = nBUFTOPTR(nb, IPHdr *);

	/* Send back to source, use our address as new source. */
	ip->ip_dst = ip->ip_src;
	ip->ip_src.s_addr = htonl(localHost);
	
	ip->ip_ttl = MAXTTL;

	icmpSend(nb, NULL);
}

/*
 * Send an icmp packet back to the ip level,
 * after supplying a checksum.
 */
#pragma argsused
static void icmpSend(
	register NBuf *nb,
	NBuf *opts
)
{
	register IPHdr *ip = nBUFTOPTR(nb, IPHdr *);
	register int ipHdrLen;
	register IcmpHdr *icp;

	/* Compute the ICMP checksum on the datagram body only. */
	ipHdrLen = ip->ip_hl << 2;
	icp = (IcmpHdr *)(nBUFTOPTR(nb, char *) + ipHdrLen);
	icp->icmp_cksum = 0;
	icp->icmp_cksum = inChkSum(nb, ip->ip_len - ipHdrLen, ipHdrLen);
	ICMPDEBUG((LOG_INFO, "icmp_send %d p%d t%d c%d from %s to %s chk=%X\n", 
				nb->len, ip->ip_p,
				icp->icmp_type, icp->icmp_code,
				ip_ntoa(ip->ip_src.s_addr), 
				ip_ntoa2(ip->ip_dst.s_addr),
				icp->icmp_cksum));
	
	ipRawOut(nb);
}

static u_long iptime(void)
{
	struct tm ctime;
	u_long t;

	if (clk_stat()) {
		gettime(&ctime);
		t = ((((u_long)ctime.tm_hour * 24
				+ (u_long)ctime.tm_min) * 60
					+ (u_long)ctime.tm_sec) * 60
#ifdef XXX	// iptime includes thousands if possible
						+ (u_long)ctime.hund
#endif
		    ) * 10;
	}
	else
		t = 0;
	return (htonl(t));
}

