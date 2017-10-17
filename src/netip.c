/*****************************************************************************
* netip.c - Network Internet Protocol (IP) program file.
*
* portions Copyright (c) 1997 by Global Election Systems Inc.
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
* 97-11-05 Guy Lancaster <lancasterg@acm.org>, Global Election Systems Inc.
*	Original.
*****************************************************************************/
/*
 * Copyright (c) 1982, 1986, 1993
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
 *	@(#)ip.h	8.2 (Berkeley) 6/1/94
 */

#include "netconf.h"
#include <string.h>
#include "net.h"
#include "netbuf.h"
#include "netip.h"
#include "netiphdr.h"

/* The upper layer interfaces. */
#include "nettcp.h"
#include "neticmp.h"

/* The lower layer interfaces. */
#include "netppp.h"

#include <stdio.h>
#include "netdebug.h"


/***********************************/
/*** LOCAL FUNCTION DECLARATIONS ***/
/***********************************/
static void ipDispatch(NBuf *nb);


/******************************/
/*** PUBLIC DATA STRUCTURES ***/
/******************************/
#if STATS_SUPPORT > 0
IPStats		ipStats;
#endif
u_short		ipID;					/* IP packet ctr, for ID fields. */
int			ip_defttl;				/* default IP ttl */
IfType		defIfType;				/* Default route interface type. */
int			defIfID;				/* Default route interface ID. */
u_long		defIPAddr;				/* Default route IP address. */

int	disable_defaultip;				/* Don't use hostname for default IP adrs */


/*****************************/
/*** LOCAL DATA STRUCTURES ***/
/*****************************/


/***********************************/
/*** PUBLIC FUNCTION DEFINITIONS ***/
/***********************************/
/*
 * ipInit - Initialize the IP subsystem.
 */
void ipInit(void)
{
#if STATS_SUPPORT > 0
	memset(&ipStats, 0, sizeof(IPStats));
	ipStats.headLine.fmtStr	    	= "\t\tIP STATISTICS\r\n";
	ipStats.ips_total.fmtStr		= "\tTOTAL DATAGRAMS: %5lu\r\n";
	ipStats.ips_toosmall.fmtStr		= "\tTOO SMALL      : %5lu\r\n";
	ipStats.ips_badvers.fmtStr		= "\tBAD VERSION    : %5lu\r\n";
	ipStats.ips_badhlen.fmtStr		= "\tBAD HEAD LENGTH: %5lu\r\n";
	ipStats.ips_badsum.fmtStr		= "\tBAD CHECKSUM   : %5lu\r\n";
	ipStats.ips_badlen.fmtStr		= "\tBAD LENGTH     : %5lu\r\n";
	ipStats.ips_buffers.fmtStr		= "\tNO FREE BUFFERS: %5lu\r\n";
	ipStats.ips_odropped.fmtStr		= "\tOTHER DROPPED  : %5lu\r\n";
	ipStats.ips_cantforward.fmtStr	= "\tCAN'T FORWARD  : %5lu\r\n";
	ipStats.ips_delivered.fmtStr		= "\tDELIVERED      : %5lu\r\n";
#endif

	ipID = 1;
	ip_defttl = IPTTLDEFAULT;
	netMask = 0;
	localHost = 0; /* OURADDR; */
	defIfType = IFT_UNSPEC;
	defIfID = 0;
	disable_defaultip = !0;
	
	icmpInit();
	setTraceLevel(LOG_WARNING, TL_IP);
}

/*
 * ipInput - Process a raw incoming IP datagram.
 */
void ipInput(NBuf *inBuf, IfType ifType, int ifID)
{
	IPHdr	*ip;
	u_char	hdrLen;
	
	/* Validate parameters. */
	if (inBuf == NULL)
		return;
	
	/* 
	 * If we don't have a default interface, assume that this interface
	 * is the one we want.
	 */
	if (defIfType == IFT_UNSPEC) {
		defIfType = ifType;
		defIfID = ifID;
	}
	
	/* Validate IP header. */
	STATS(ipStats.ips_total.val++;)
	if (inBuf->len < sizeof(IPHdr) &&
		    (inBuf = nPullup(inBuf, sizeof(IPHdr))) == NULL) {
		STATS(ipStats.ips_toosmall.val++;)
		IPDEBUG((LOG_ERR, TL_IP, "ipInput: Runt packet len %u", inBuf->len));
		goto abortInput;
	}
	ip = nBUFTOPTR(inBuf, IPHdr *);
	if (ip->ip_v != IPVERSION) {
		STATS(ipStats.ips_badvers.val++;)
		IPDEBUG((LOG_ERR, TL_IP, "ipInput: Bad version %u", ip->ip_v));
		goto abortInput;
	}
	hdrLen = ip->ip_hl << 2;
	if (hdrLen < sizeof(IPHdr)) {	/* minimum header length */
		STATS(ipStats.ips_badhlen.val++;)
		IPDEBUG((LOG_ERR, TL_IP, "ipInput: Bad hdr sz %u", hdrLen));
		goto abortInput;
	}
	if (hdrLen > inBuf->len) {
		if ((inBuf = nPullup(inBuf, hdrLen)) == NULL) {
			STATS(ipStats.ips_badhlen.val++;)
			goto abortInput;
		}
		ip = nBUFTOPTR(inBuf, IPHdr *);
	}
	if ((ip->ip_sum = inChkSum(inBuf, hdrLen, 0)) != 0) {
		STATS(ipStats.ips_badsum.val++;)
		IPDEBUG((LOG_ERR, TL_IP, "ipInput: Bad IP chksum"));
		goto abortInput;
	}
	
	/*
	 * Convert fields to host representation.
	 */
	NTOHS(ip->ip_len);
	if (ip->ip_len < hdrLen) {
		STATS(ipStats.ips_badlen.val++;)
		goto abortInput;
	}
	NTOHS(ip->ip_id);
	NTOHS(ip->ip_off);

	/*
	 * Adjust ip_len to not reflect header.
	 * XXX This makes it confusing since packets sent to ipRawOut()
	 * would have a normal header but other packets would not!
	ip->ip_len -= hdrLen;
	 */
	
	/* Pass the datagram along and we're done. */
	ipDispatch(inBuf);
	return;
	
abortInput:
#if DEBUG_SUPPORT > 0
	nDumpChain(inBuf);
#endif
	nFreeChain(inBuf);
	return;
}

/* 
 * ipSend - Build and send an IP datagram.
 * The Type-Of-Service is defaulted, we don't handle fragmentation, the
 * Time-To-Live is defaulted, and we don't support IP options.
 */
#pragma argsused
void ipSend(
	u_char protocol, 			/* IP protocol. */
	u_long srcAddr, 			/* Source IP address in network byte order. */
	u_long dstAddr, 			/* Destination IP address in network byte order. */
	NBuf *outBuf				/* Datagram to send. */
)
{
	IPHdr ipHdr;
	
	if (outBuf) {
		/* Build the IP header. */
		memset(&ipHdr, 0, sizeof(IPHdr));
		ipHdr.ip_v = IPVERSION;
		ipHdr.ip_hl = sizeof(IPHdr) / 4;
		ipHdr.ip_tos = 0;				/* Default Type-Of-Service */
		ipHdr.ip_len = outBuf->chainLen + sizeof(IPHdr);
		ipHdr.ip_id = IPNEWID();
		ipHdr.ip_off = 0;				/* Sorry - no fragments. */
		ipHdr.ip_ttl = ip_defttl;
		ipHdr.ip_p = protocol;
		ipHdr.ip_src.s_addr = srcAddr;
		ipHdr.ip_dst.s_addr = dstAddr;
		
		/* Prepend an IP header. */
		nPREPEND(outBuf, &ipHdr, sizeof(IPHdr));
		if (outBuf == NULL) {
			STATS(ipStats.ips_odropped.val++;)
		} else		
			/* Send the datagram. */
			ipDispatch(outBuf);
	}
}

/* 
 * ipRawOut - Send a prepared IP datagram.
 * This is where route lookup could occur.
 */
void ipRawOut(NBuf *nb)
{
	ipDispatch(nb);
}


/*
 * ripInput - Handle raw ICMP packets.
 */
void ripInput(NBuf *nb)
{
	IPDEBUG((LOG_INFO, TL_IP, "rip_input: dropping packet"));
	nFreeChain(nb);
	STATS(ipStats.ips_odropped.val++;)
}


/*
 * ipIOCtl - Get and set IP I/O configuration.
 */
#pragma argsused
int  ipIOCtl(INT cmd, void *arg)
{
	return 0;
}

/*
 * ipOptStrip - Strip off the options from the head of the buffer.
 * If the operation fails (likely failure to allocate a new nBuf),
 * then the situation is considered unrecoverable and the buffer
 * chain is dropped.
 * Return the resulting buffer chain.
 */
NBuf *ipOptStrip(NBuf *inBuf, u_int ipHeadLen)
{
	int optSize = ipHeadLen - sizeof(IPHdr);
	NBuf *n0;
	
	if (optSize < 0 || (n0 = nSplit(inBuf, ipHeadLen)) == NULL) {
		nFreeChain(inBuf);
		inBuf = NULL;
		STATS(ipStats.ips_odropped.val++;)
	} else if (nTrim(NULL, &inBuf, -optSize) < optSize) {
		nFreeChain(n0);
		nFreeChain(inBuf);
		inBuf = NULL;
		STATS(ipStats.ips_odropped.val++;)
	} else
		inBuf = nCat(inBuf, n0);
	
	return inBuf;
}

/*
 * ipMTU - Return the size in bytes of the Maximum Transmission Unit for the
 * given destination or zero if the destination is not reachable.
 */
u_int ipMTU(u_long dstAddr)
{
	u_int st;
	
	if (dstAddr == htonl(localHost) || dstAddr == htonl(LOOPADDR))
		st = NBUFSZ;
		
	else switch (defIfType) {
	case IFT_PPP:
		st = pppMTU(defIfID);
		break;
	default:
		st = 0;
		break;
	}
	
	IPDEBUG((LOG_INFO, TL_IP, "ipMTU: dst %s => %u", ip_ntoa(dstAddr), st));
	return st;
}

/*
 * ipSetDefault - set the default route.
 */
void ipSetDefault(u_int32_t l, u_int32_t g, IfType ifType, int ifID)
{
	localHost = ntohl(l);
	defIPAddr = g;
	defIfType = ifType;
	defIfID = ifID;
	IPDEBUG((LOG_INFO, TL_IP, "ipSetDefault: %s %s %d %d",
				ip_ntoa(l), 
				ip_ntoa2(g),
				ifType, ifID));
}

/*
 * ipClearDefault - clear the default route.
 */
void ipClearDefault(void)
{
	defIPAddr = 0;
	defIfType = IFT_UNSPEC;
	defIfID = 0;
	IPDEBUG((LOG_INFO, TL_IP, "ipClearDefault"));
}

/*
 * Make a string representation of a network IP address.
 * WARNING: NOT RE-ENTRANT!
 */
char *ip_ntoa(u_int32_t ipaddr)
{
	static char b[20];
	
	ipaddr = ntohl(ipaddr);
	
	sprintf(b, "%d.%d.%d.%d",
			(u_char)(ipaddr >> 24),
			(u_char)(ipaddr >> 16),
			(u_char)(ipaddr >> 8),
			(u_char)(ipaddr));
	return b;
}
/* A second buffer if you want 2 addresses in one printf. */
char *ip_ntoa2(u_int32_t ipaddr)
{
	static char b[20];
	
	ipaddr = ntohl(ipaddr);
	
	sprintf(b, "%d.%d.%d.%d",
			(u_char)(ipaddr >> 24),
			(u_char)(ipaddr >> 16),
			(u_char)(ipaddr >> 8),
			(u_char)(ipaddr));
	return b;
}

/*
 * Make a string representation of a host IP address.
 * WARNING: NOT RE-ENTRANT!
 */
char *ip_htoa(u_int32_t ipaddr)
{
	static char b[20];
		
	sprintf(b, "%d.%d.%d.%d",
			(u_char)(ipaddr >> 24),
			(u_char)(ipaddr >> 16),
			(u_char)(ipaddr >> 8),
			(u_char)(ipaddr));
	return b;
}

/**********************************/
/*** LOCAL FUNCTION DEFINITIONS ***/
/**********************************/
/*
 * ipDispatch - Dispatch a "prepared" IP datagram according to it's source
 * and destination IP addresses and its protocol.
 * By prepared, the buffer's data pointer references the start of the IP
 * header and the length, identification, and offset fields are in HOST
 * byte order.  The IP address fields are in network byte order.
 */
static void ipDispatch(NBuf *outBuf)
{
	IPHdr 	*ip			= nBUFTOPTR(outBuf, IPHdr *);
	u_char	hdrLen		= ip->ip_hl * 4;
	u_long	srcAddr		= ip->ip_src.s_addr;
	u_long	dstAddr		= ip->ip_dst.s_addr;
	
	IPDEBUG((LOG_INFO, TL_IP, "ipDispatch: len %u proto %u to %s from %s tos %d",
				ip->ip_len, ip->ip_p,
				ip_ntoa(dstAddr), 
				ip_ntoa2(srcAddr),
				ip->ip_tos));
	
	/* Validata the IP header. */
	if (ip->ip_len < hdrLen) {
		IPDEBUG((LOG_ERR, TL_IP, "ipDispatch: Dropped short len %u proto %u to %s from %s", 
				 ip->ip_len,
				 ip->ip_p,
				 ip_ntoa(dstAddr), 
				 ip_ntoa2(srcAddr)));
		STATS(ipStats.ips_badlen.val++;)
		nFreeChain(outBuf);
	}
	
	/* If destined for us, dispatch according to the protocol. */
	/* 
	 * Note: We catch the loopback address here instead of passing it
	 * to a loopback interface so that this one dispatch function may
	 * handle both input and output. 
	 */
	else if (dstAddr == htonl(localHost) || dstAddr == htonl(LOOPADDR)) {
		switch (ip->ip_p) {
		case IPPROTO_ICMP:
			icmpInput(outBuf, hdrLen);
			break;
		case IPPROTO_TCP:
			tcpInput(outBuf, hdrLen);
			break;
		default:
			IPDEBUG((LOG_ERR, TL_IP, 
					 "ipDispatch: Dropped bad protocol %d, len %u from %s to %s",
					 ip->ip_p,
					 ip->ip_len,
					 ip_ntoa(dstAddr), 
					 ip_ntoa2(srcAddr)));
			nFreeChain(outBuf);
			STATS(ipStats.ips_odropped.val++;)
		}
	}
	
	/*
	 * Otherwise, if not from us, we're not a router so drop it.
	 * XXX We could (should?) send an ICMP message. 
	 */
	else if (srcAddr != htonl(localHost)) {
		IPDEBUG((LOG_ERR, TL_IP,
				 "ipDispatch: Dropped can't fwd len %u proto %u to %s from %s",
				 ip->ip_len, ip->ip_p,
				 ip_ntoa(dstAddr), 
				 ip_ntoa2(srcAddr)));
		STATS(ipStats.ips_cantforward.val++;)
		nFreeChain(outBuf);
	}
	
	/* If we made it here, send it out. */
	else switch (defIfType) {
	case IFT_PPP:
		/* Convert fields to network representation. */
		HTONS(ip->ip_len);
		HTONS(ip->ip_id);
		HTONS(ip->ip_off);
		
		/* Checksum the header. */
		ip->ip_sum = 0;
		ip->ip_sum = inChkSum(outBuf, hdrLen, 0);
		
		pppOutput(defIfID, PPP_IP, outBuf);
		STATS(ipStats.ips_delivered.val++;)
		break;
	default:
		IPDEBUG((LOG_ERR, TL_IP,
				 "ipDispatch: Dropped bad if %d len %u proto %u to %s from %s", 
				 defIfType,
				 ip->ip_len, ip->ip_p,
				 ip_ntoa(dstAddr), 
				 ip_ntoa2(srcAddr)));
		nFreeChain(outBuf);
		STATS(ipStats.ips_odropped.val++;)
		break;
	}
}


