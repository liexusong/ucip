/*****************************************************************************
* netip.h - Network Internet Protocol header file.
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
* $Id: netip.h,v 1.1.1.1 2000/10/16 04:36:14 guylancaster Exp $
*
******************************************************************************
* REVISION HISTORY
*
* 98-11-05 Guy Lancaster <glanca@gesn.com>, Global Election Systems Inc.
*	Original.
*****************************************************************************/

#ifndef NETIP_H
#define NETIP_H

/*************************
*** PUBLIC DEFINITIONS ***
*************************/


/************************
*** PUBLIC DATA TYPES ***
************************/
typedef struct {
	DiagStat headLine;		/* Head line for display. */
	DiagStat ips_total;
	DiagStat ips_toosmall;
	DiagStat ips_badvers;
	DiagStat ips_badhlen;
	DiagStat ips_badsum;
	DiagStat ips_badlen;
	DiagStat ips_odropped;
	DiagStat ips_buffers;
	DiagStat ips_cantforward;
	DiagStat ips_delivered;
	DiagStat endRec;
} IPStats;


/*****************************
*** PUBLIC DATA STRUCTURES ***
*****************************/
extern u_short		ipID;		/* IP datagram ctr, for ID fields. */
#if STATS_SUPPORT > 0
extern IPStats		ipStats;     /* IP statistics. */
#endif
extern int			ip_defttl;	/* default IP ttl */
extern IfType		defIfType;	/* Default route interface type. */
extern int			defIfID;	/* Default route interface ID. */
extern u_long		defIPAddr;	/* Default route IP address. */

extern int	disable_defaultip;	/* Don't use hostname for default IP adrs */


/***********************
*** PUBLIC FUNCTIONS ***
***********************/
/*
 * ipInit - Initialize the IP subsystem.
 */
void ipInit(void);

/*
 * ipInput - Process a raw incoming IP datagram.
 */
void ipInput(NBuf *mb, IfType ifType, int ifID);

/* 
 * ipSend - Build and send an IP datagram.
 * The Type-Of-Service is defaulted, we don't handle fragmentation, the
 * Time-To-Live is defaulted, and we don't support IP options.
 */
void ipOutput(u_char protocol, NBuf *outBuf);

/* 
 * ipRawOut - Send a prepared IP datagram.
 */
void ipRawOut(NBuf *outBuf);

/*
 * ripInput - Handle raw ICMP packets.
 */
void ripInput(NBuf *nb);

/*
 * ipIOCtl - Get and set IP I/O configuration.
 */
int  ipIOCtl(INT cmd, void *arg);

/*
 * ipOptStrip - Strip off the options from the head of the buffer.
 * If the operation fails (likely failure to allocate a new nBuf),
 * then the situation is considered unrecoverable and the buffer
 * chain is dropped.
 * Return the resulting buffer chain.
 */
NBuf *ipOptStrip(NBuf *inBuf, u_int ipHeadLen);

/*
 * ipMTU - Return the size in bytes of the Maximum Transmission Unit for the
 * given destination or zero if the destination is not reachable.
 */
u_int ipMTU(u_long dstAddr);

/*
 * ipSetDefault - set the default route.
 */
void ipSetDefault(u_int32_t l, u_int32_t g, IfType ifType, int ifID);

/*
 * ipClearDefault - clear the default route.
 */
void ipClearDefault(void);

/*
 * Make a string representation of a network IP address.
 * WARNING: NOT RE-ENTRANT!
 */
char *ip_ntoa(u_int32_t ipaddr);
/* A second buffer if you want 2 addresses in one printf. */
char *ip_ntoa2(u_int32_t ipaddr);

char *ip_htoa(u_int32_t ipaddr);

/*
 * IPNEWID - Return a new IP identification field value.
 */
#define IPNEWID() (ipID++)


#endif
