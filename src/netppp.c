/*****************************************************************************
* netppp.c - Network Point to Point Protocol program file.
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
 * ppp_defs.h - PPP definitions.
 *
 * if_pppvar.h - private structures and declarations for PPP.
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
 * if_ppp.h - Point-to-Point Protocol definitions.
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
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "netconf.h"
#include <string.h>
#include "net.h"
#include "netrand.h"
#include "netbuf.h"
#include "netfsm.h"
#if PAP_SUPPORT > 0
#include "netpap.h"
#endif
#if CHAP_SUPPORT > 0
#include "netchap.h"
#endif
#include "netipcp.h"
#include "netlcp.h"
#include "netiphdr.h"		/* Required for netvj.h. */
#if VJ_SUPPORT > 0
#include "netvj.h"
#endif
#include "netppp.h"

/* Upper layer protocols. */
#include "netip.h"

/* Lower layer interfaces. */
#include <stdio.h>

#include "netdebug.h"


/*************************/
/*** LOCAL DEFINITIONS ***/
/*************************/
/*
 *	Configuration parameters.
 */
#define MAXIDLEFLAG	500					/* Max Xmit idle time before resend flag char. */
#define MAXKILLDELAY TICKSPERSEC		/* Max delay jiffys before PPP task checks kill. */
#define STACK_SIZE NETSTACK+512		/* Enough to handle printf's. */

#define MAX_IFS		32


/*
 * The basic PPP frame.
 */
#define PPP_HDRLEN	4			/* octets for standard ppp header */
#define PPP_FCSLEN	2			/* octets for FCS */
#define PPP_ADDRESS(p)	(((u_char *)(p))[0])
#define PPP_CONTROL(p)	(((u_char *)(p))[1])
#define PPP_PROTOCOL(p)	((((u_char *)(p))[2] << 8) + ((u_char *)(p))[3])

/* PPP packet parser states.  Current state indicates operation yet to be
 * completed. */
typedef enum {
	PDIDLE = 0,					/* Idle state - waiting. */
	PDSTART,					/* Process start flag. */
	PDADDRESS,					/* Process address field. */
	PDCONTROL,					/* Process control field. */
	PDPROTOCOL1,				/* Process protocol field 1. */
	PDPROTOCOL2,				/* Process protocol field 2. */
	PDDATA						/* Process data byte. */
} PPPDevStates;

/* Special character codes. */
#define PPPFLAG 0x7e			/* Flag character. */
#define PPPESCAPE 0x7d			/* Escape character. */
#define PPPESCMASK 0x20			/* Mask to x-or with escaped character. */
#define PPPADDRESS 0xff			/* All-stations address. */
#define PPPCONTROL 0x03			/* Unnumbered info. */
/*
 * Significant octet values.
 */
#define	PPP_ALLSTATIONS	0xff	/* All-Stations broadcast address */
#define	PPP_UI		0x03		/* Unnumbered Information */
#define	PPP_FLAG	0x7e		/* Flag Sequence */
#define	PPP_ESCAPE	0x7d		/* Asynchronous Control Escape */
#define	PPP_TRANS	0x20		/* Asynchronous transparency modifier */

/*
 * Protocol field values.
 */
#define PPP_IP		0x21		/* Internet Protocol */
#define	PPP_XNS		0x25		/* Xerox NS */
#define PPP_AT		0x29		/* AppleTalk Protocol */
#define PPP_IPX		0x2b		/* IPX Datagram (RFC1552) */
#define	PPP_VJC_COMP	0x2d	/* VJ compressed TCP */
#define	PPP_VJC_UNCOMP	0x2f	/* VJ uncompressed TCP */
#define PPP_COMP	0xfd		/* compressed packet */
#define PPP_IPCP	0x8021		/* IP Control Protocol */
#define PPP_ATCP	0x8029		/* AppleTalk Control Protocol */
#define PPP_IPXCP	0x802b		/* IPX Control Protocol (RFC1552) */
#define PPP_CCP		0x80fd		/* Compression Control Protocol */
#define PPP_LCP		0xc021		/* Link Control Protocol */
#define PPP_PAP		0xc023		/* Password Authentication Protocol */
#define PPP_LQR		0xc025		/* Link Quality Report protocol */
#define PPP_CHAP	0xc223		/* Cryptographic Handshake Auth. Protocol */
#define PPP_CBCP	0xc029		/* Callback Control Protocol */

/*
 * Values for FCS calculations.
 */
#define PPP_INITFCS	0xffff		/* Initial FCS value */
#define PPP_GOODFCS	0xf0b8		/* Good final FCS value */
#define PPP_FCS(fcs, c)	(((fcs) >> 8) ^ fcstab[((fcs) ^ (c)) & 0xff])

/*
 * Bit definitions for flags.
 */
#define SC_COMP_PROT	0x00000001	/* protocol compression (output) */
#define SC_COMP_AC		0x00000002	/* header compression (output) */
#define	SC_COMP_TCP		0x00000004	/* TCP (VJ) compression (output) */
#define SC_NO_TCP_CCID	0x00000008	/* disable VJ connection-id comp. */
#define SC_REJ_COMP_AC	0x00000010	/* reject adrs/ctrl comp. on input */
#define SC_REJ_COMP_TCP	0x00000020	/* reject TCP (VJ) comp. on input */
#define SC_CCP_OPEN		0x00000040	/* Look at CCP packets */
#define SC_CCP_UP		0x00000080	/* May send/recv compressed packets */
#define SC_DEBUG		0x00010000	/* enable debug messages */
#define SC_LOG_INPKT	0x00020000	/* log contents of good pkts recvd */
#define SC_LOG_OUTPKT	0x00040000	/* log contents of pkts sent */
#define SC_LOG_RAWIN	0x00080000	/* log all chars received */
#define SC_LOG_FLUSH	0x00100000	/* log all chars flushed */
#define SC_RCV_B7_0		0x01000000	/* have rcvd char with bit 7 = 0 */
#define SC_RCV_B7_1		0x02000000	/* have rcvd char with bit 7 = 1 */
#define SC_RCV_EVNP		0x04000000	/* have rcvd char with even parity */
#define SC_RCV_ODDP		0x08000000	/* have rcvd char with odd parity */
#define	SC_MASK			0x0fff00ff	/* bits that user can change */

/*
 * State bits in sc_flags, not changeable by user.
 */
#define SC_TIMEOUT		0x00000400	/* timeout is currently pending */
#define SC_VJ_RESET		0x00000800	/* need to reset VJ decomp */
#define SC_COMP_RUN		0x00001000	/* compressor has been initiated */
#define SC_DECOMP_RUN	0x00002000	/* decompressor has been initiated */
#define SC_DC_ERROR		0x00004000	/* non-fatal decomp error detected */
#define SC_DC_FERROR	0x00008000	/* fatal decomp error detected */
#define SC_TBUSY		0x10000000	/* xmitter doesn't need a packet yet */
#define SC_PKTLOST		0x20000000	/* have lost or dropped a packet */
#define	SC_FLUSH		0x40000000	/* flush input until next PPP_FLAG */
#define	SC_ESCAPED		0x80000000	/* saw a PPP_ESCAPE */


                                                                                                                                        
/************************/
/*** LOCAL DATA TYPES ***/
/************************/
/*
 * PPP interface control block.
 */
typedef struct PPPControl_s {
	char ifname[IFNAMSIZ];				/* Interface name */
	char openFlag;						/* True when in use. */
	char oldFrame;						/* Old framing character for fd. */
	int  fd;							/* File device ID of port. */
	int  kill_link;						/* Shut the link down. */
	int  if_up;							/* True when the interface is up. */
	int  errCode;						/* Code indicating why interface is down. */
	char pppStack[STACK_SIZE];			/* The ppp task stack. */
	NBuf *inHead, *inTail;				/* The input packet. */
	PPPDevStates inState;				/* The input process state. */
	char inEscaped;						/* Escape next character. */
	u_int inProtocol;					/* The input protocol code. */
	u_int inFCS;						/* Input Frame Check Sequence value. */
	u_int inLen;						/* Input packet length. */
	int  mtu;							/* Peer's mru */
	int  pcomp;							/* Does peer accept protocol compression? */
	int  accomp;						/* Does peer accept addr/ctl compression? */
	u_long lastXMit;					/* Time of last transmission. */
	ext_accm inACCM;					/* Async-Ctl-Char-Map for input. */
	ext_accm outACCM;					/* Async-Ctl-Char-Map for output. */
#if VJ_SUPPORT > 0
	int  vjEnabled;						/* Flag indicating VJ compression enabled. */
	struct vjcompress vjComp;			/* Van Jabobsen compression header. */
#endif
	int traceOffset;					/* Trace level offset. */
} PPPControl;


/*
 * Ioctl definitions.
 */

struct npioctl {
    int		protocol;			/* PPP procotol, e.g. PPP_IP */
    enum NPmode	mode;
};



/***********************************/
/*** LOCAL FUNCTION DECLARATIONS ***/
/***********************************/
static void pppMain(void *pd);
static void pppDispatch(int pd, NBuf *nb, u_int protocol);
static void pppDrop(PPPControl *pc);
static void pppInProc(int pd, u_char *s, int l);
static NBuf *pppMPutC(u_char c, ext_accm *outACCM, NBuf *nb);
static NBuf *pppMPutRaw(u_char c, NBuf *nb);

#define ESCAPE_P(accm, c) ((accm)[(c) >> 3] & pppACCMMask[c & 0x07])

/* For development use only. */

/******************************/
/*** PUBLIC DATA STRUCTURES ***/
/******************************/
int	auth_required = 0;			/* Peer is required to authenticate */
PPPControl pppControl[NUM_PPP];	/* The PPP interface control blocks. */
#if STATS_SUPPORT > 0
PPPStats pppStats;				/* Statistics. */
#endif

/*
 * PPP Data Link Layer "protocol" table.
 * One entry per supported protocol.
 * The last entry must be NULL.
 */
struct protent *protocols[] = {
	&lcp_protent,
#if PAP_SUPPORT > 0
	&pap_protent,
#endif
#if CHAP_SUPPORT > 0
	&chap_protent,
#endif
#if CBCP_SUPPORT > 0
	&cbcp_protent,
#endif
	&ipcp_protent,
#if CCP_SUPPORT	> 0
	&ccp_protent,
#endif
    NULL
};

/*
 * Buffers for outgoing packets.  This must be accessed only from the appropriate
 * PPP task so that it doesn't need to be protected to avoid collisions.
 */
u_char outpacket_buf[NUM_PPP][PPP_MRU+PPP_HDRLEN];	



/*****************************/
/*** LOCAL DATA STRUCTURES ***/
/*****************************/

/*
 * FCS lookup table as calculated by genfcstab.
 */
const u_short fcstab[256] = {
	0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
	0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
	0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
	0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
	0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
	0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
	0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
	0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
	0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
	0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
	0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
	0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
	0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
	0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
	0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
	0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
	0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
	0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
	0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
	0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
	0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
	0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
	0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
	0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
	0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
	0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
	0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
	0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
	0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
	0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
	0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
	0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

/* PPP's Asynchronous-Control-Character-Map.  The mask array is used
 * to select the specific bit for a character. */
static u_char pppACCMMask[] = {
	0x01,
	0x02,
	0x04,
	0x08,
	0x10,
	0x20,
	0x40,
	0x80
};


/***********************************/
/*** PUBLIC FUNCTION DEFINITIONS ***/
/***********************************/
/* Initialize the PPP subsystem. */
void pppInit(void)
{
	struct protent *protp;
	int i, j;
	
	for (i = 0; i < NUM_PPP; i++) {
		pppControl[i].openFlag = 0;
		sprintf(pppControl[i].ifname, "ppp%d", i);
	
		/*
		 * Initialize to the standard option set.
		 */
		for (j = 0; (protp = protocols[j]) != NULL; ++j)
			(*protp->init)(i);
	}
	
#if STATS_SUPPORT > 0
	/* Clear the statistics. */
	memset(&pppStats, 0, sizeof(pppStats));
	pppStats.headLine.fmtStr		= "\t\tPPP STATISTICS\r\n";
	pppStats.ppp_ibytes.fmtStr		= "\tBYTES IN    : %5lu\r\n";
	pppStats.ppp_ipackets.fmtStr	= "\tPACKETS IN  : %5lu\r\n";
	pppStats.ppp_ierrors.fmtStr		= "\tIN ERRORS   : %5lu\r\n";
	pppStats.ppp_derrors.fmtStr		= "\tDISPATCH ERR: %5lu\r\n";
	pppStats.ppp_obytes.fmtStr		= "\tBYTES OUT   : %5lu\r\n";
	pppStats.ppp_opackets.fmtStr	= "\tPACKETS OUT : %5lu\r\n";
	pppStats.ppp_oerrors.fmtStr		= "\tOUT ERRORS  : %5lu\r\n";
#endif
}

/* Open a new PPP connection using the given I/O device.
 * This initializes the PPP control block but does not
 * attempt to negotiate the LCP session.  If this port
 * connects to a modem, the modem connection must be
 * established before calling this.
 * Return a new PPP connection descriptor on success or
 * an error code (negative) on failure. */
int pppOpen(int fd)
{
	PPPControl *pc;
	char c;
	int pd;
	
	/* XXX
	 * Ensure that fd is not already used for PPP
	 */

	/* Find a free PPP session descriptor. */
	OS_ENTER_CRITICAL();
	for (pd = 0; pd < NUM_PPP && pppControl[pd].openFlag != 0; pd++);
	if (pd >= NUM_PPP)
		pd = PPPERR_OPEN;
	else
		pppControl[pd].openFlag = !0;
	OS_EXIT_CRITICAL();

	/*
	 * Save the old line discipline of fd, and set it to PPP.
	 *	(For the Accu-Vote, save and set the framing character).
	 *	Set the user name and password in case we need PAP
	 *	authentication.
	 */
	if (pd >= 0) {
		c = PPP_FLAG;
#ifdef OS_DEPENDENT
		if (ioctl(fd, GETFRAME, &pppControl[pd].oldFrame) < 0
				|| ioctl(fd, SETFRAME, &c) < 0) {
			pd = PPPERR_DEVICE;
			pppControl[pd].openFlag = 0;
		}
#else
		pppControl[pd].openFlag = 0;
#endif
		upap_setloginpasswd(pd, user, passwd);
	}
	
	/* Launch a deamon thread. */
	if (pd >= 0) {
		lcp_init(pd);
		pc = &pppControl[pd];
		pc->fd = fd;
		pc->kill_link = 0;
		pc->if_up = 0;
		pc->errCode = 0;
		pc->inState = PDIDLE;
		pc->inHead = NULL;
		pc->inTail = NULL;
		pc->inEscaped = 0;
		pc->lastXMit = mtime() - MAXIDLEFLAG;
		pc->traceOffset = 0;
		
#if VJ_SUPPORT > 0
		pc->vjEnabled = 0;
		vj_compress_init(&pc->vjComp);
#endif

		/* 
		 * Default the in and out accm so that escape and flag characters
		 * are always escaped. 
		 */
		memset(pc->inACCM, 0, sizeof(ext_accm));
		pc->inACCM[15] = 0x60;
		memset(pc->outACCM, 0, sizeof(ext_accm));
		pc->outACCM[15] = 0x60;
		
#ifdef OS_DEPENDENT
		OSTaskCreate(pppMain, (void *)pd, pc->pppStack + STACK_SIZE, PRI_PPP0 + pd);
#endif
	
		while(pd >= 0 && !pc->if_up) {
			msleep(500);
			if (lcp_phase[pd] == PHASE_DEAD) {
				pppClose(pd);
				if (pc->errCode)
					pd = pc->errCode;
				else
					pd = PPPERR_CONNECT;
			}
		}
		pc->traceOffset = 2;
	}

	return pd;
}

/* Close a PPP connection and release the descriptor. 
 * Any outstanding packets in the queues are dropped.
 * Return 0 on success, an error code on failure. */
int pppClose(int pd)
{
	PPPControl *pc = &pppControl[pd];
	int st = 0;

	/* Disconnect */
	pc->kill_link = !0;
	pc->traceOffset = 0;
	
	while(st >= 0 && lcp_phase[pd] != PHASE_DEAD) {
		msleep(500);
	}

#ifdef OS_DEPENDENT
	/* Reset fd line discipline.  In our case, the framing character. */
	if (ioctl(pc->fd, SETFRAME, &pppControl[pd].oldFrame) < 0)
		st = PPPERR_DEVICE;
#endif
		
	pc->openFlag = 0;
	
	return st;
}

/* Send a packet on the given connection.
 * Return 0 on success, an error code on failure. */
#pragma argsused
int pppOutput(int pd, u_short protocol, NBuf *nb)
{
	PPPControl *pc = &pppControl[pd];
	u_int fcsOut = PPP_INITFCS;
	NBuf *headMB = NULL, *tailMB = NULL, *tnb;
	int st = 0;
	u_char c = 0;
	int n;
	u_char *sPtr;

	/* Grab an output buffer. */
	nGET(headMB);
	if (headMB == NULL) {
		st = PPPERR_ALLOC;
		PPPDEBUG((LOG_WARNING, TL_PPP, "pppOutput[%d]: first alloc fail", pd));
#if STATS_SUPPORT > 0
		pppStats.PPPoerrors++;
#endif
	
	/* Validate parameters. */
	/* We let any protocol value go through - it can't hurt us
	 * and the peer will just drop it if it's not accepting it. */
	} else if (pd < 0 || pd >= NUM_PPP || !pc->openFlag || !nb) {
		st = PPPERR_PARAM;
		PPPDEBUG((LOG_WARNING, TL_PPP, "pppOutput[%d]: bad parms prot=%d nb=%P",
					pd, protocol, nb));
#if STATS_SUPPORT > 0
		pppStats.PPPoerrors++;
#endif
		
	/* Check that the link is up. */
	} else if (lcp_phase[pd] == PHASE_DEAD) {
		PPPDEBUG((LOG_ERR, TL_PPP, "pppOutput[%d]: link not up", pd));
#if STATS_SUPPORT > 0
		pppStats.PPPderrors++;
#endif
		st = PPPERR_OPEN;
		
	} else {
#if VJ_SUPPORT > 0
		/* 
		 * Attempt Van Jacobson header compression if VJ is configured and
		 * this is an IP packet. 
		 */
		if (protocol == PPP_IP && pc->vjEnabled) {
			switch (vj_compress_tcp(&pc->vjComp, nb)) {
			case TYPE_IP:
				/* No change...
				protocol = PPP_IP_PROTOCOL;
				 */
				break;
			case TYPE_COMPRESSED_TCP:
				protocol = PPP_VJC_COMP;
				break;
			case TYPE_UNCOMPRESSED_TCP:
				protocol = PPP_VJC_UNCOMP;
				break;
			default:
				PPPDEBUG((LOG_WARNING, TL_PPP, "pppOutput[%d]: bad IP packet", pd));
#if STATS_SUPPORT > 0
				pppStats.PPPderrors++;
#endif
				return PPPERR_PROTOCOL;
			}
		}
#endif
		
		headMB->len = 0;
		tailMB = headMB;
			
		/* Build the PPP header. */
		if (diffTime(pc->lastXMit) <= MAXIDLEFLAG)
			tailMB = pppMPutRaw(PPP_FLAG, tailMB);
		if (!pc->accomp) {
			fcsOut = PPP_FCS(fcsOut, PPP_ALLSTATIONS);
			tailMB = pppMPutC(PPP_ALLSTATIONS, &pc->outACCM, tailMB);
			fcsOut = PPP_FCS(fcsOut, PPP_UI);
			tailMB = pppMPutC(PPP_UI, &pc->outACCM, tailMB);
		}
		if (!pc->pcomp || protocol > 0xFF) {
			c = (protocol >> 8) & 0xFF;
			fcsOut = PPP_FCS(fcsOut, c);
			tailMB = pppMPutC(c, &pc->outACCM, tailMB);
		}
		c = protocol & 0xFF;
		fcsOut = PPP_FCS(fcsOut, c);
		tailMB = pppMPutC(c, &pc->outACCM, tailMB);
		
		/* Load packet. */
		while (nb) {
			sPtr = nBUFTOPTR(nb, u_char *);
			n = nb->len;
			while (n-- > 0) {
				c = *sPtr++;
				
				/* Update FCS before checking for special characters. */
				fcsOut = PPP_FCS(fcsOut, c);
				
				/* Copy to output buffer escaping special characters. */
				tailMB = pppMPutC(c, &pc->outACCM, tailMB);
			}
			nFREE(nb, tnb);
			nb = tnb;
		}
			
		/* Add FCS and trailing flag. */
		c = ~fcsOut & 0xFF;
		tailMB = pppMPutC(c, &pc->outACCM, tailMB);
		c = (~fcsOut >> 8) & 0xFF;
		tailMB = pppMPutC(c, &pc->outACCM, tailMB);
		tailMB = pppMPutRaw(PPP_FLAG, tailMB);
			
		/* If we failed to complete the packet, throw it away.
		 * Otherwise send it. */
		if (!tailMB) {
			st = PPPERR_ALLOC;
			PPPDEBUG((pppControl[pd].traceOffset + LOG_WARNING, TL_PPP,
						"pppOutput[%d]: Alloc err - dropping proto=%d", 
						pd, protocol));
			nFreeChain(headMB);
#if STATS_SUPPORT > 0
			pppStats.PPPoerrors++;
#endif
		}
		else {
			PPPDEBUG((pppControl[pd].traceOffset + LOG_INFO, TL_PPP,
						"pppOutput[%d]: proto=x%X %d:%.*H", 
						pd, protocol,
						headMB->chainLen, MIN(headMB->len * 2, 50), headMB->data));
			nPut(pc->fd, headMB);
#if STATS_SUPPORT > 0
			pppStats.PPPopackets++;
#endif
		}
		headMB = NULL;
	}
	/* If we didn't consume the source buffer, drop it. */
	if (nb)
		nFreeChain(nb);
	/* If we didn't send the output buffer, drop it. */
	if (headMB) {
		nFreeChain(headMB);
#if STATS_SUPPORT > 0
		pppStats.PPPoerrors++;
#endif
	}
		
	return st;
}

/* Process an nBuf chain received on given connection.
 * The nBuf chain is always passed on or freed making the original
 * nBuf pointer invalid.  Note that this does not check for packet
 * chains.  This does not require complete packets but if a packet
 * spans calls, those calls must be in the correct order.  This is
 * designed to handle packets received from the serial interface
 * but could be used for a loopback interface.
 * Return 0 on success, an error code on failure.
 */
int pppInput(int pd, NBuf *nb)
{
	NBuf *nextNBuf;

	while (nb != NULL) {
		/* Consume the buffer.  Ideally we could just work on the
		 * recieved buffer but unless we get the serial driver to
		 * preprocess the escape sequences, it's easier to just
		 * work from one buffer to another. */
		pppInProc(pd, nb->data, nb->len);
		nFREE(nb, nextNBuf);
		nb = nextNBuf;
	}
	return 0;
}

/* Get and set parameters for the given connection.
 * Return 0 on success, an error code on failure. */
int  pppIOCtl(int pd, int cmd, void *arg)
{
	PPPControl *pc = &pppControl[pd];
	int st = 0;

	if (pd < 0 || pd >= NUM_PPP)
		st = PPPERR_PARAM;
	else {
		switch(cmd) {
		case PPPCTLG_UPSTATUS:		/* Get the PPP up status. */
			if (arg) 
				*(int *)arg = (int)(pc->if_up);
			else
				st = PPPERR_PARAM;
			break;
		case PPPCTLS_ERRCODE:		/* Set the PPP error code. */
			if (arg) 
				pc->errCode = *(int *)arg;
			else
				st = PPPERR_PARAM;
			break;
		case PPPCTLG_ERRCODE:		/* Get the PPP error code. */
			if (arg) 
				*(int *)arg = (int)(pc->errCode);
			else
				st = PPPERR_PARAM;
			break;
		case PPPCTLG_FD:
			if (arg) 
				*(int *)arg = (int)(pc->fd);
			else
				st = PPPERR_PARAM;
			break;
		default:
			st = PPPERR_PARAM;
			break;
		}
	}
	
	return st;
}

/*
 * Return the Maximum Transmission Unit for the given PPP connection.
 */
u_int pppMTU(int pd)
{
	PPPControl *pc = &pppControl[pd];
	u_int st;
	
	/* Validate parameters. */
	if (pd < 0 || pd >= NUM_PPP || !pc->openFlag)
		st = 0;
	else
		st = pc->mtu;
		
	return st;
}

/*
 * Write n characters to a ppp link.
 *	RETURN: >= 0 Number of characters written
 *		 	 -1 Failed to write to device
 */
int pppWrite(int pd, const char *s, int n)
{
	PPPControl *pc = &pppControl[pd];
	short st = 0;
	u_char c;
	u_int fcsOut = PPP_INITFCS;
	NBuf *headMB = NULL, *tailMB;

	nGET(headMB);
	if (headMB == NULL) {
		st = PPPERR_ALLOC;
#if STATS_SUPPORT > 0
		pppStats.PPPoerrors++;
#endif
	} else {
		headMB->len = 0;
		tailMB = headMB;
		
		/* If the link has been idle, we'll send a fresh flag character to
		 * flush any noise. */
		if (diffTime(pc->lastXMit) <= MAXIDLEFLAG)
			tailMB = pppMPutRaw(PPP_FLAG, tailMB);
		pc->lastXMit = mtime();
		 
		/* Load output buffer. */
		while (n-- > 0) {
			c = *s++;
			
			/* Update FCS before checking for special characters. */
			fcsOut = PPP_FCS(fcsOut, c);
			
			/* Copy to output buffer escaping special characters. */
			tailMB = pppMPutC(c, &pc->outACCM, tailMB);
		}
		
		/* Add FCS and trailing flag. */
		c = ~fcsOut & 0xFF;
		tailMB = pppMPutC(c, &pc->outACCM, tailMB);
		c = (~fcsOut >> 8) & 0xFF;
		tailMB = pppMPutC(c, &pc->outACCM, tailMB);
		tailMB = pppMPutRaw(PPP_FLAG, tailMB);
		
		/* If we failed to complete the packet, throw it away.
		 * Otherwise send it. */
		if (tailMB) {
			PPPDEBUG((pppControl[pd].traceOffset + LOG_INFO, TL_PPP,
						"pppWrite[%d]: %d:%.*H", 
						pd,
						headMB->len, MIN(headMB->len * 2, 40), headMB->data));
			nPut(pc->fd, headMB);
#if STATS_SUPPORT > 0
			pppStats.PPPopackets++;
#endif
		}
		else {
			PPPDEBUG((pppControl[pd].traceOffset + LOG_WARNING, TL_PPP,
						"pppWrite[%d]: Alloc err - dropping %d:%.*H", 
						pd,
						headMB->len, MIN(headMB->len * 2, 40), headMB->data));
			nFreeChain(headMB);
#if STATS_SUPPORT > 0
			pppStats.PPPoerrors++;
#endif
		}
	}
	
	return st;
}

/*
 * ppp_send_config - configure the transmit characteristics of
 * the ppp interface.
 */
void ppp_send_config(
	int unit, 
	int mtu,
	u_int32_t asyncmap,
	int pcomp, 
	int accomp
)
{
	PPPControl *pc = &pppControl[unit];
	int i;
	
	pc->mtu = mtu;
	pc->pcomp = pcomp;
	pc->accomp = accomp;
	
	/* Load the ACCM bits for the 32 control codes. */
	for (i = 0; i < 32/8; i++)
		pc->outACCM[i] = (u_char)((asyncmap >> (8 * i)) & 0xFF);
	PPPDEBUG((LOG_INFO, TL_PPP, "ppp_send_config[%d]: outACCM=%X %X %X %X",
				unit,
				pc->outACCM[0], pc->outACCM[1], pc->outACCM[2], pc->outACCM[3]));
}


/*
 * ppp_set_xaccm - set the extended transmit ACCM for the interface.
 */
void ppp_set_xaccm(int unit, ext_accm *accm)
{
	memcpy(pppControl[unit].outACCM, accm, sizeof(ext_accm));
	PPPDEBUG((LOG_INFO, TL_PPP, "ppp_set_xaccm[%d]: outACCM=%X %X %X %X",
				unit,
				pppControl[unit].outACCM[0],
				pppControl[unit].outACCM[1],
				pppControl[unit].outACCM[2],
				pppControl[unit].outACCM[3]));
}


/*
 * ppp_recv_config - configure the receive-side characteristics of
 * the ppp interface.
 */
#pragma argsused /* XXX */
void ppp_recv_config(
	int unit, 
	int mru,
	u_int32_t asyncmap,
	int pcomp, 
	int accomp
)
{
	PPPControl *pc = &pppControl[unit];
	int i;
	
	/* Load the ACCM bits for the 32 control codes. */
	for (i = 0; i < 32 / 8; i++)
		pc->inACCM[i] = (u_char)(asyncmap >> (i * 8));
	PPPDEBUG((LOG_INFO, TL_PPP, "ppp_recv_config[%d]: inACCM=%X %X %X %X",
				unit,
				pc->inACCM[0], pc->inACCM[1], pc->inACCM[2], pc->inACCM[3]));
}

/*
 * ccp_test - ask kernel whether a given compression method
 * is acceptable for use.  Returns 1 if the method and parameters
 * are OK, 0 if the method is known but the parameters are not OK
 * (e.g. code size should be reduced), or -1 if the method is unknown.
 */
#pragma argsused
int ccp_test(
	int unit, 
	int opt_len, 
	int for_transmit,
	u_char *opt_ptr
)
{
	return 0;	/* XXX Currently no compression. */
}

/*
 * ccp_flags_set - inform kernel about the current state of CCP.
 */
#pragma argsused
void ccp_flags_set(int unit, int isopen, int isup)
{
	/* XXX */
}

/*
 * ccp_fatal_error - returns 1 if decompression was disabled as a
 * result of an error detected after decompression of a packet,
 * 0 otherwise.  This is necessary because of patent nonsense.
 */
#pragma argsused
int ccp_fatal_error(int unit)
{
	/* XXX */
	return 0;
}

/*
 * get_idle_time - return how long the link has been idle.
 */
#pragma argsused
int get_idle_time(int u, struct ppp_idle *ip)
{	
	/* XXX */
	return 0;
}


/*
 * Return user specified netmask, modified by any mask we might determine
 * for address `addr' (in network byte order).
 * Here we scan through the system's list of interfaces, looking for
 * any non-point-to-point interfaces which might appear to be on the same
 * network as `addr'.  If we find any, we OR in their netmask to the
 * user-specified netmask.
 */
u_int32_t GetMask(u_int32_t addr)
{
	u_int32_t mask, nmask;
	
	htonl(addr);
	if (IN_CLASSA(addr))	/* determine network mask for address class */
		nmask = IN_CLASSA_NET;
	else if (IN_CLASSB(addr))
		nmask = IN_CLASSB_NET;
	else
		nmask = IN_CLASSC_NET;
	/* class D nets are disallowed by bad_ip_adrs */
	mask = netMask | htonl(nmask);
	
	/* XXX
	 * Scan through the system's network interfaces.
	 * Get each netmask and OR them into our mask.
	 */
	
	return mask;
}

/*
 * sifvjcomp - config tcp header compression
 */
#pragma argsused
int sifvjcomp(
	int pd, 
	int vjcomp, 
	int cidcomp, 
	int maxcid
)
{
#if VJ_SUPPORT > 0
	PPPControl *pc = &pppControl[pd];
	
	pc->vjEnabled = vjcomp;
	pc->vjComp.compressSlot = cidcomp;
	pc->vjComp.maxSlotIndex = maxcid;
	PPPDEBUG((LOG_INFO, TL_PPP, "sifvjcomp: VJ compress enable=%d slot=%d max slot=%d",
				vjcomp, cidcomp, maxcid));
#endif

	return 0;
}

/*
 * sifup - Config the interface up and enable IP packets to pass.
 */
#pragma argsused
int sifup(int pd)
{
	PPPControl *pc = &pppControl[pd];
	int st = 1;
	
	if (pd < 0 || pd >= NUM_PPP || !pc->openFlag) {
		st = 0;
		PPPDEBUG((LOG_WARNING, TL_PPP, "sifup[%d]: bad parms", pd));
	} else {
	    pc->if_up = 1;
	    pc->errCode = 0;
	}
	return st;
}

/*
 * sifnpmode - Set the mode for handling packets for a given NP.
 */
#pragma argsused
int sifnpmode(int u, int proto, enum NPmode mode)
{
	return 0;
}

/*
 * sifdown - Config the interface down and disable IP.
 */
#pragma argsused
int sifdown(int pd)
{
	PPPControl *pc = &pppControl[pd];
	int st = 1;
	
	if (pd < 0 || pd >= NUM_PPP || !pc->openFlag) {
		st = 0;
		PPPDEBUG((LOG_WARNING, TL_PPP, "sifup[%d]: bad parms", pd));
	} else
	    pc->if_up = 0;
	return st;
}

/*
 * sifaddr - Config the interface IP addresses and netmask.
 */
#pragma argsused
int sifaddr(
	int u,				/* Interface unit ??? */
	u_int32_t o,		/* Our IP address ??? */
	u_int32_t h,		/* IP subnet mask ??? */
	u_int32_t m			/* IP broadcast address ??? */
)
{
	return 1;
}

/*
 * cifaddr - Clear the interface IP addresses, and delete routes
 * through the interface if possible.
 */
#pragma argsused
int cifaddr(
	int u, 			/* Interface unit ??? */
	u_int32_t o,	/* Our IP address ??? */
	u_int32_t h		/* IP broadcast address ??? */
)
{
	return 1;
}

/*
 * sifdefaultroute - assign a default route through the address given.
 */
#pragma argsused
int sifdefaultroute(int u, u_int32_t l, u_int32_t g)
{
	ipSetDefault(l, g, IFT_PPP, u);
	return !0;
}

/*
 * cifdefaultroute - delete a default route through the address given.
 */
#pragma argsused
int cifdefaultroute(int u, u_int32_t l, u_int32_t g)
{
	ipClearDefault();
	return !0;
}

/**********************************/
/*** LOCAL FUNCTION DEFINITIONS ***/
/**********************************/
/* The main PPP process function.  This implements the state machine according
 * to section 4 of RFC 1661: The Point-To-Point Protocol. */
static void pppMain(void *pd)
{
	PPPControl *pc = &pppControl[(int)pd];
	NBuf *curNBuf;
	
	/*
	 * Start the connection and handle incoming events (packet or timeout).
	 */
	trace(LOG_NOTICE, "Connecting %s <--> %s", pc->ifname, nameForDevice(pc->fd));
	lcp_lowerup((int)pd);
	lcp_open((int)pd);		/* Start protocol */
	while (lcp_phase[(int)pd] != PHASE_DEAD) {
		if (pc->kill_link) {
			/* This will leave us at PHASE_DEAD. */
			lcp_close(0, "User request");
			pc->kill_link = 0;
		}
		else {
			nGet(pc->fd, &curNBuf, MAXKILLDELAY);
			avRandomize();
			if (curNBuf != NULL) {
				pppInput((int)pd, curNBuf);
				/* curNBuf is invalid now so we don't need to free it. */
			}
		}
	}

#ifdef OS_DEPENDENT
	OSTaskDel(OS_PRIO_SELF);
#endif
}

/*
 * Pass the processed input packet to the appropriate handler.
 */
static void pppDispatch(int pd, NBuf *nb, u_int protocol)
{
	if (nb != NULL) {
		switch(protocol) {
		case PPP_LCP:			/* Link Control Protocol */
			PPPDEBUG((pppControl[pd].traceOffset + LOG_INFO, TL_PPP,
						"pppDispatch[%d]: lcp in %d:%.*H", 
						pd, nb->len, MIN(nb->len * 2, 40), nb->data));
			/* XXX Assume that LCP packet fits in single nBuf. */
			lcp_protent.input(pd, nb->data, nb->len);
			nFreeChain(nb);
		    break;
		case PPP_IPCP:			/* IP Control Protocol */
			PPPDEBUG((pppControl[pd].traceOffset + LOG_INFO, TL_PPP,
						"pppDispatch[%d]: ipcp in %d:%.*H", 
						pd, nb->len, MIN(nb->len * 2, 40), nb->data));
			/* XXX Assume that IPCP packet fits in single nBuf. */
			ipcp_protent.input(pd, nb->data, nb->len);
			nFreeChain(nb);
			break;
		case PPP_PAP:			/* Password Authentication Protocol */
			PPPDEBUG((pppControl[pd].traceOffset + LOG_INFO, TL_PPP,
						"pppDispatch[%d]: pap in %d:%.*H", 
						pd, nb->len, MIN(nb->len * 2, 40), nb->data));
			pap_protent.input(pd, nb->data, nb->len);
			nFreeChain(nb);
		    break;
		case PPP_VJC_COMP:		/* VJ compressed TCP */
#if VJ_SUPPORT > 0
			PPPDEBUG((pppControl[pd].traceOffset + LOG_INFO, TL_PPP,
						"pppDispatch[%d]: vj_comp in %d:%.*H", 
						pd, nb->len, MIN(nb->len * 2, 40), nb->data));
			/* 
			 * Clip off the VJ header and prepend the rebuilt TCP/IP header and
			 * pass the result to IP.
			 */
			if (vj_uncompress_tcp(&nb, &pppControl[pd].vjComp) >= 0) {
				ipInput(nb, IFT_PPP, pd);
			} else {
				/* Something's wrong so drop it. */
				PPPDEBUG((pppControl[pd].traceOffset + LOG_WARNING, TL_PPP,
							"pppDispatch[%d]: Dropping VJ compressed", pd));
				nFreeChain(nb);
			}
#else
			/* No handler for this protocol so drop the packet. */
			PPPDEBUG((pppControl[pd].traceOffset + LOG_INFO, TL_PPP,
						"pppDispatch[%d]: drop VJ Comp in %d:.*H", 
						pd, nb->len, MIN(nb->len * 2, 40), nb->data));
			nFreeChain(nb);
#if STATS_SUPPORT > 0
			pppStats.PPPderrors++;
#endif
#endif
			break;
		case PPP_VJC_UNCOMP:	/* VJ uncompressed TCP */
#if VJ_SUPPORT > 0
			PPPDEBUG((pppControl[pd].traceOffset + LOG_INFO, TL_PPP,
						"pppDispatch[%d]: vj_un in %d:%.*H", 
						pd, nb->len, MIN(nb->len * 2, 40), nb->data));
			/* 
			 * Process the TCP/IP header for VJ header compression and then pass
			 * the packet to IP.
			 */
			if (vj_uncompress_uncomp(nb, &pppControl[pd].vjComp) >= 0) {
				ipInput(nb, IFT_PPP, pd);
			} else {
				/* Something's wrong so drop it. */
				PPPDEBUG((pppControl[pd].traceOffset + LOG_WARNING, TL_PPP,
							"pppDispatch[%d]: Dropping VJ uncompressed", pd));
				nFreeChain(nb);
			}
#else
			/* No handler for this protocol so drop the packet. */
			PPPDEBUG((pppControl[pd].traceOffset + LOG_INFO, TL_PPP,
						"pppDispatch[%d]: drop VJ UnComp in %d:.*H", 
						pd, nb->len, MIN(nb->len * 2, 40), nb->data));
			nFreeChain(nb);
#if STATS_SUPPORT > 0
			pppStats.PPPderrors++;
#endif
#endif
			break;
		case PPP_IP:			/* Internet Protocol */
			PPPDEBUG((pppControl[pd].traceOffset + LOG_INFO, TL_PPP,
						"pppDispatch[%d]: ip in %d:%.*H", 
						pd, nb->len, MIN(nb->len * 2, 40), nb->data));
			ipInput(nb, IFT_PPP, pd);
			break;
		case PPP_AT:			/* AppleTalk Protocol */
		case PPP_COMP:			/* compressed packet */
		case PPP_ATCP:			/* AppleTalk Control Protocol */
		case PPP_CCP:			/* Compression Control Protocol */
		case PPP_LQR:			/* Link Quality Report protocol */
		case PPP_CHAP:			/* Cryptographic Handshake Auth. Protocol */
		case PPP_CBCP:			/* Callback Control Protocol */
		default:
			/* No handler for this protocol so drop the packet. */
			PPPDEBUG((pppControl[pd].traceOffset + LOG_INFO, TL_PPP,
						"pppDispatch[%d]: drop 0x%X in %d:%.*H", 
						pd, protocol, nb->len, MIN(nb->len * 2, 40), nb->data));
			nFreeChain(nb);
#if STATS_SUPPORT > 0
			pppStats.PPPderrors++;
#endif
			break;
		}
	}
}


/*
 * Drop the input packet.
 */
static void pppDrop(PPPControl *pc)
{
	if (pc->inHead != NULL) {
		PPPDEBUG((LOG_INFO, TL_PPP, "pppDrop: %d:%.*H", 
					pc->inHead->len, 
					min(60, pc->inHead->len * 2), 
					pc->inHead->data));
		nFreeChain(pc->inHead);
		pc->inHead = NULL;
		pc->inTail = NULL;
	}
#if VJ_SUPPORT > 0
	vj_uncompress_err(&pc->vjComp);
#endif
}


/*
 * Process a received octet string.
 */
static void pppInProc(int pd, u_char *s, int l)
{
	PPPControl *pc = &pppControl[pd];
	NBuf *nextNBuf;
	u_char curChar;

	while (l-- > 0) {
		curChar = *s++;
		
		/* Handle special characters. */
		if (ESCAPE_P(pc->inACCM, curChar)) {
			/* Check for escape sequences. */
			/* XXX Note that this does not handle an escaped 0x5d character which
			 * would appear as an escape character.  Since this is an ASCII ']'
			 * and there is no reason that I know of to escape it, I won't complicate
			 * the code to handle this case. GLL */
			if (curChar == PPPESCAPE)
				pc->inEscaped = !0;
			/* Check for the flag character. */
			else if (curChar == PPPFLAG) {
				/* If this is just an extra flag character, ignore it. */
				if (pc->inState == PDADDRESS)
					;
				/* If we haven't received the packet header, drop what has come in. */
				else if (pc->inState < PDDATA) {
					PPPDEBUG((pc->traceOffset + LOG_WARNING, TL_PPP,
								"pppInProc[%d]: Dropping incomplete packet %d", 
								pd, pc->inState));
					pppDrop(pc);
				}
				/* If the fcs is invalid, drop the packet. */
				else if (pc->inFCS != PPP_GOODFCS) {
					PPPDEBUG((pc->traceOffset + LOG_INFO, TL_PPP,
								"pppInProc[%d]: Dropping bad fcs 0x%X proto=x%X", 
								pd, pc->inFCS, pc->inProtocol));
					pppDrop(pc);
#if STATS_SUPPORT > 0
					pppStats.PPPierrors++;
#endif
				}
				/* Otherwise it's a good packet so pass it on. */
				else {
					/* Trim off the checksum. */
					pc->inTail->len -= 2;
					pc->inLen -= 2;
					
					/* Update the packet header. */
					pc->inHead->chainLen = pc->inLen;
					
					/* Dispatch the packet thereby consuming it. */
					pppDispatch(pd, pc->inHead, pc->inProtocol);
					pc->inHead = NULL;
					pc->inTail = NULL;

#if STATS_SUPPORT > 0
					pppStats.PPPipackets++;
#endif
				}
					
				/* Prepare for a new packet. */
				pc->inFCS = PPP_INITFCS;
				pc->inState = PDADDRESS;
				pc->inEscaped = 0;
			}
			/* Other characters are usually control characters that may have
			 * been inserted by the physical layer so here we just drop them. */
			else {
				PPPDEBUG((pc->traceOffset + LOG_WARNING, TL_PPP,
							"pppInProc[%d]: Dropping ACCM char <%d>", pd, curChar));
			}
		}
		/* Process other characters. */
		else {
			/* Unencode escaped characters. */
			if (pc->inEscaped) {
				pc->inEscaped = 0;
				curChar ^= PPPESCMASK;
			}
			
			/* Having removed transparency encoding and physical layer control characters,
			 * we can update the frame check sequence nunber. */
			pc->inFCS = PPP_FCS(pc->inFCS, curChar);
			
			/* Process character relative to current state. */
			switch(pc->inState) {
			case PDIDLE:					/* Idle state - waiting. */
				/* Drop the character. */
				break;
			case PDSTART:					/* Process start flag. */
				/* Drop the character - we would have processed a flag character
				 * above. */
				break;
			case PDCONTROL:					/* Process control field. */
				/* If we don't get a valid control code, restart. */
				if (curChar == PPPCONTROL) {
					pc->inState = PDPROTOCOL1;
				}
				else {
					PPPDEBUG((pc->traceOffset + LOG_WARNING, TL_PPP,
								"pppInProc[%d]: Invalid control <%d>", pd, curChar));
					pc->inState = PDSTART;
				}
				break;
			case PDADDRESS:					/* Process address field. */
				if (curChar == PPPADDRESS) {
					pc->inState = PDCONTROL;
					break;
				}
				/* Else assume compressed address and control fields so
				 * fall through to get the protocol... */
			case PDPROTOCOL1:				/* Process protocol field 1. */
				/* If the lower bit is set, this is the end of the protocol
				 * field. */
				if (curChar & 1) {
					pc->inProtocol = curChar;
					pc->inState = PDDATA;
				}
				else {
					pc->inProtocol = (u_int)curChar << 8;
					pc->inState = PDPROTOCOL2;
				}
				break;
			case PDPROTOCOL2:				/* Process protocol field 2. */
				pc->inProtocol |= curChar;
				pc->inState = PDDATA;
				break;
			case PDDATA:					/* Process data byte. */
				/* Make space to receive processed data. */
				if (pc->inTail == NULL || nTRAILINGSPACE(pc->inTail) <= 0) {
					/* If we haven't started a packet, we need a packet header. */
					nGET(nextNBuf);
					if (nextNBuf == NULL) {
						/* No free buffers.  Drop the input packet and let the
						 * higher layers deal with it.  Continue processing
						 * the received nBuf chain in case a new packet starts. */
						PPPDEBUG((LOG_ERR, TL_PPP, "pppInProc[%d]: NO FREE MBUFS!", pd));
						pppDrop(pc);
						pc->inState = PDSTART;	/* Wait for flag sequence. */
						pc->inFCS = PPP_INITFCS;
					} else {
						*(nextNBuf->data) = curChar;
						nextNBuf->len = 1;
						nextNBuf->nextBuf = NULL;
						if (pc->inHead == NULL) {
							pc->inHead = nextNBuf;
							pc->inLen = 1;
						}
						else {	/* Since if inHead is not NULL, then neither is inTail! */
							pc->inTail->nextBuf = nextNBuf;
							pc->inLen++;
						}
						pc->inTail = nextNBuf;
					}
				}
				/* Load character into buffer. */
				else {
					pc->inTail->data[pc->inTail->len++] = curChar;
					pc->inLen++;
				}
				break;
			}
		}
	}
}

/* 
 * pppMPutC - append given character to end of given nBuf.  If the character
 * needs to be escaped, do so.  If nBuf is full, append another.
 * Return the current nBuf.
 */
static NBuf *pppMPutC(u_char c, ext_accm *outACCM, NBuf *nb)
{
	NBuf *tb = nb;
	
	/* Make sure there is room for the character and an escape code.
	 * Sure we don't quite fill the buffer if the character doesn't
	 * get escaped but is one character worth complicating this? */
	/* Note: We assume no packet header. */
	if (nb && (&nb->body[NBUFSZ] - (nb->data + nb->len)) < 2) {
		nGET(tb);
		if (tb) {
			nb->nextBuf = tb;
			tb->len = 0;
		}
		nb = tb;
	}
	if (nb) {
		if (ESCAPE_P(*outACCM, c)) {
			*(nb->data + nb->len++) = PPP_ESCAPE;
			*(nb->data + nb->len++) = c ^ PPP_TRANS;
		}
		else
			*(nb->data + nb->len++) = c;
	}
		
	return tb;
}

/* 
 * pppMPutRaw - append given character to end of given nBuf without escaping
 * it.  If nBuf is full, append another.
 * This is normally used to add the flag character to a packet.
 * Return the current nBuf.
 */
static NBuf *pppMPutRaw(u_char c, NBuf *nb)
{
	NBuf *tb = nb;
	
	/* Make sure there is room for the character and an escape code.
	 * Sure we don't quite fill the buffer if the character doesn't
	 * get escaped but is one character worth complicating this? */
	/* Note: We assume no packet header. */
	if (nb && (&nb->body[NBUFSZ] - (nb->data + nb->len)) < 2) {
		nGET(tb);
		if (tb) {
			nb->nextBuf = tb;
			tb->len = 0;
		}
		nb = tb;
	}
	if (nb) {
		*(nb->data + nb->len++) = c;
	}
		
	return tb;
}



