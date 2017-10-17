/*****************************************************************************
* nettcp.c - Network Transport Control Protocol program file.
*
* Copyright (c) 1998 by Global Election Systems Inc.  All rights reserved.
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
* 98-02-02 Guy Lancaster <glanca@gesn.com>, Global Election Systems Inc.
*	Original based on ka9q and BSD codes.
******************************************************************************
* NOTES
*
* MAXIMUM WINDOW
*	We use a signed short int for the segment size adjustment (trimSeg()) to
* allow returning error codes.  Thus our maximum segment size must be <=
* INT_MAX (i.e. 32767) rather than MAX_UINT.  This is not a problem
* considering that we are using a PPP link over a serial link.
*
* HEADER CACHE
*	The header values are all loaded in the header caches before being
* written to the outgoing segment so that a debugger can see the values
* of the header last sent.
******************************************************************************
* TO DO
*
* -	Implement a SENDFIN flag in the tcb flags and use it in tcpOutput().
* - FINISH close!
*****************************************************************************/

#include "netconf.h"
#include <string.h>
#include "net.h"
#include "nettimer.h"
#include "netbuf.h"
#include "netrand.h"
#include "netip.h"
#include "netiphdr.h"
#include "nettcp.h"
#include "nettcphd.h"

#include <stdio.h>
#include "netdebug.h"


/*************************/
/*** LOCAL DEFINITIONS ***/
/*************************/
/* Configuration */
#define MAXTCP 6			/* Maximum TCP connections incl listeners. */
#define TCPTTL 64			/* Default time-to-live for TCP datagrams. */
#define OPTSPACE 5*4		/* TCP options space - must be a multiple of 4. */
#define	NTCB	16			/* # TCB hash table headers */
#define MAXRETRANS 12		/* Maximum retransmissions. */
#define MAXKEEPTIMES 10		/* Maximum keep alive probe timeouts. */
#define MAXLISTEN 2			/* Maximum queued cloned listen connections. */
#define MAXFINWAIT2 600L	/* Max time in seconds to wait for peer FIN. */
#define WRITESLEEP TICKSPERSEC /* Sleep time write waits for buffers (jiffies). */
#define STACK_SIZE NETSTACK	/* Minimal stack. */


/*
 * TCP connection control flag masks.
 */
#define	FORCE	1		/* We owe the other end an ACK or window update */
#define	CLONE	2		/* Server-type TCB, cloned on incoming SYN */
#define	RETRAN	4		/* A retransmission has occurred */
#define	ACTIVE	8		/* TCB created with an active open */
#define	SYNACK	16		/* Our SYN has been acked */
#define KEEPALIVE 32	/* Send a keepalive probe */

/* Round trip timing parameters */
#define	AGAIN	8	/* Average RTT gain = 1/8 */
#define	DGAIN	4	/* Mean deviation gain = 1/4 */
#define	MSL2	30	/* Guess at two maximum-segment lifetimes in seconds */


/* procInFlags return codes. */
#define ACKOK	0		/* OK to process segment. */
#define ACKDROP -1		/* Drop the segment. */
#define ACKRESET -2		/* Return segment as a reset. */
#define ACKCLOSE -3		/* Close the connection. */


/************************/
/*** LOCAL DATA TYPES ***/
/************************/
/*
 * Combined TCP/IP headers with no options.  Used to cached the headers.
 */
typedef	struct TcpIPHdr_s {
	IPHdr  ipHdr;		/* IP header - no options. */
	TCPHdr tcpHdr;		/* TCP header.  tcpSeq, ack, off, & win
						 * are in host byte order.
						 */
	char options[OPTSPACE];	/* Cache for TCP options. */
} TCPIPHdr;

/*
 * TCP connection states.
 */
typedef enum {
	CLOSED = 0,		/* Must be 0 */
	LISTEN = 1,
	SYN_SENT= 2,
	SYN_RECEIVED = 3,
	ESTABLISHED = 4,
	FINWAIT1 = 5,
	FINWAIT2 = 6,
	CLOSE_WAIT = 7,
	CLOSING	= 8,
	LAST_ACK = 9,
	TIME_WAIT = 10
} TCPState;


/*
 * TCP session close reason codes.
 */
typedef enum {
	NORMAL = 0,		/* Normal close */
	RESET = 1,		/* Reset by other end */
	TIMEOUT = 2,	/* Excessive retransmissions */
	NETWORK = 3		/* Network problem (ICMP message) */
} TCPReason;



/*
 * TCP connection control block.
 */
typedef struct TCPCB_s {
	struct TCPCB_s *prev;	/* Linked list pointers for hash table */
	struct TCPCB_s *next;
	Connection conn;		/* Connection struct for hash lookup. */	

	TCPState state;			/* Connection state */

	int freeOnClose;		/* Flag set to free TCB on close. */
	int closeReason;		/* Reason for closing - TCPERR_ or 0 */
	int traceLevel;			/* Trace level this connection. */

	/*
	 * Send sequence variables.
	 */
	struct {
	u_int32_t una;	/* First unacknowledged sequence number */
	u_int32_t nxt;	/* Next sequence num to be sent for the first time */
	u_int32_t ptr;	/* Working transmission pointer */
		u_int16_t wnd;	/* Other end's offered receive window */
	u_int32_t wl1;	/* Sequence number used for last window update */
	u_int32_t wl2;	/* Ack number used for last window update */
	} snd;
u_int32_t iss;			/* Initial send sequence number */
	u_int16_t cwind;		/* Congestion window */
	u_int16_t ssthresh;		/* Slow-start threshold */
u_int32_t resent;		/* Count of bytes retransmitted */

	/* Receive sequence variables */
	struct {
	u_int32_t nxt;		/* Incoming sequence number expected next */
		u_int16_t wnd;		/* Our offered receive window */
		u_int16_t up;		/* Receive urgent pointer */
	} rcv;
u_int32_t irs;			/* Initial receive sequence number */
	u_int16_t mss;			/* Maximum segment size */
u_int32_t rerecv;		/* Count of duplicate bytes received */
	
	int minFreeBufs;	/* Minimum free buffers before we'll queue something. */

	char backoff;		/* Backoff interval */
	char flags;			/* Control flags */

	int listenQOpen;	/* Max queued listen connections. */
	int listenQHead;	/* Head of cloned TCB queue. */
	int listenQTail;	/* Tail of cloned TCB queue. */
	struct TCPCB_s 
		*listenQ[MAXLISTEN + 1];	/* Circular queue of clones. */
	
	NBufQHdr rcvq;		/* Receive queue */
	u_int16_t rcvcnt;		/* Bytes on receive queue. */
	NBuf *rcvBuf;		/* Hold one buffer while we trim it. */

	NBufQHdr sndq;		/* Send queue */
	u_int16_t sndcnt;		/* Number of unacknowledged sequence numbers on
						 * send queue. NB: includes SYN and FIN, which don't
						 * actually appear on sndq!
						 */

	NBufQHdr *reseq;		/* Out-of-order segment queue */
	Timer resendTimer;			/* Timeout timer */
	u_int32 retransTime;	/* Retransmission time - 0 for none. */
	u_int retransCnt;		/* Retransmission count at current wl2. */
	u_int32 rttStart;		/* Start time for round trip measurement. */
u_int32_t rttseq;			/* Sequence number being timed */
u_int32_t srtt;				/* Smoothed round trip time, milliseconds */
u_int32_t mdev;				/* Mean deviation, milliseconds */
	
	u_long keepAlive;		/* Keepalive in Jiffys - 0 for none. */
	int keepProbes;			/* Number of keepalive probe timeouts. */
	u_long keepTime;		/* Jiffy time of keepalive timeout. */
	Timer keepTimer;		/* Keep alive timer */
	    
    OS_EVENT *connectSem;	/* Semaphore for connect requests. */
	OS_EVENT *readSem;		/* Semaphore for read function. */
	OS_EVENT *writeSem;		/* Semaphore for write function. */
	OS_EVENT *mutex;		/* Mutex for tcpOutput TCB variables. */
	
	TCPIPHdr hdrCache;		/* Cached TCP/IP header. */
	char *optionsPtr;		/* Ptr into TCP options area. */
} TCPCB;

/* 
 * Shorthand for common fields.
 */
#define ipVersion	hdrCache.ipHdr.ip_v
#define ipHdrLen	hdrCache.ipHdr.ip_hl
#define ipTOS		hdrCache.ipHdr.ip_tos
#define ipLen		hdrCache.ipHdr.ip_len		/* Host byte order! */
#define ipIdent		hdrCache.ipHdr.ip_id		/* Host byte order! */
#define ipTTL		hdrCache.ipHdr.ip_ttl
#define ipProto		hdrCache.ipHdr.ip_p
#define ipSrcAddr	hdrCache.ipHdr.ip_src.s_addr /* Network byte order! */
#define ipDstAddr	hdrCache.ipHdr.ip_dst.s_addr /* Network byte order! */
#define tcpSrcPort	hdrCache.tcpHdr.srcPort		/* Network byte order! */
#define tcpDstPort	hdrCache.tcpHdr.dstPort		/* Network byte order! */
#define tcpSeq		hdrCache.tcpHdr.seq			/* Network byte order! */
#define tcpAck		hdrCache.tcpHdr.ack			/* Network byte order! */
#define tcpHdrLen	hdrCache.tcpHdr.tcpOff
#define tcpFlags	hdrCache.tcpHdr.flags
#define tcpWin		hdrCache.tcpHdr.win			/* Network byte order! */
#define tcpCkSum	hdrCache.tcpHdr.ckSum
#define tcpUrgent	hdrCache.tcpHdr.urgent		/* Network byte order! */
#define tcpOptions	hdrCache.options


/***********************************/
/*** LOCAL FUNCTION DECLARATIONS ***/
/***********************************/
static void tcpEcho(void *arg);
static void resendTimeout(void *arg);
static void keepTimeout(void *arg);
static void setState(TCPCB *tcb, TCPState newState);
static int procInFlags(TCPCB *tcb, TCPHdr *tcpHdr, IPHdr *ipHdr);
static void tcbInit(register TCPCB *tcb);
static void tcbUpdate(register TCPCB *tcb, register TCPHdr *tcpHdr);
static void procSyn(register TCPCB *tcb, TCPHdr *tcpHdr);
static void sendSyn(register TCPCB *tcb);
static void closeSelf(register TCPCB *tcb, int reason);
static u_int32_t newISS(void);
static void tcpOutput(TCPCB *tcb);
static u_int tcbHash(Connection *conn);
static void tcbLink(register TCPCB *tcb);
static void tcbUnlink(register TCPCB *tcb);
static TCPCB * tcbLookup(Connection *conn);
static void tcbFree(TCPCB *tcb);
static void tcpReset(
	NBuf *inBuf,				/* The input segment. */
	IPHdr *ipHdr,				/* The IP header in the segment. */
	TCPHdr *tcpHdr,				/* The TCP header in the segment. */
	u_int16_t segLen				/* The TCP segment length. */
);
static INT tcpdValid(UINT tcpd);

/*
 * trimSeg - Trim segment to fit window. 
 * Return the new segment length, -1 if segment is unaccepable.
 */
static int trimSeg(
	register TCPCB *tcb,
	register TCPHdr *tcpHdr,
	NBuf *nb,
	u_int hdrLen,
	u_int16_t segLen
);

/* 
 * backOff - Backoff function - the subject of much research.
 *
 * Use binary exponential up to retry #4, and quadratic after that
 * This yields the sequence
 * 1, 2, 4, 8, 16, 25, 36, 49, 64, 81, 100 ...
 */
#define backOff(n) ((n) <= 4 ? 1 << (n) : (n) * (n))

/* 
 * Sequence number comparisons.
 */
#define seqWithin(x, low, high) \
(((low) <= (high)) ? ((low) <= (x) && (x) <= (high)) : ((low) >= (x) && (x) >= (high)))
#define seqLT(x, y) ((long)((x) - (y)) < 0)
#define seqLE(x,y) ((long)((x) - (y)) <= 0)
#define seqGT(x,y) ((long)((x) - (y)) > 0)
#define seqGE(x,y) ((long)((x) - (y)) >= 0)

/*
 * Determine if the given sequence number is in our receiver window.
 * NB: must not be used when window is closed!
 */
#define inWindow(tcb, seq) \
	seqWithin((seq), (tcb)->rcv.nxt, (u_int32_t)((tcb)->rcv.nxt + (tcb)->rcv.wnd - 1))

/*
 * Put a data in host order into a char array in network order
 * and advance the pointer. 
 */
#define put32(cp, x) (*((u_int32 *)(cp))++ = ntohl(x))
#define put16(cp, x) (*((u_int16_t *)(cp))++ = ntohs(x))

/*
 * Operators for the cloned listen connection queue.  These should be
 * used within a critical section.
 */
#define listenQLen(tcb) \
	((tcb)->listenQHead > (tcb)->listenQTail \
		? (tcb)->listenQHead - (tcb)->listenQTail \
		: (tcb)->listenQTail - (tcb)->listenQHead)
#define listenQEmpty(tcb) ((tcb)->listenQHead == (tcb)->listenQTail)
#define listenQPush(tcb, ntcb) { \
	OS_ENTER_CRITICAL(); \
	if (listenQLen((tcb)) < (tcb)->listenQOpen) { \
		(tcb)->listenQ[(tcb)->listenQHead] = (ntcb); \
		(tcb)->listenQHead = ((tcb)->listenQHead + 1) % MAXLISTEN; \
	} \
	OS_EXIT_CRITICAL(); \
}
#define listenQPop(tcb, ntcbp) { \
	if ((tcb)->listenQHead != (tcb)->listenQTail) { \
		*(ntcbp) = (tcb)->listenQ[(tcb)->listenQTail]; \
		(tcb)->listenQTail = ((tcb)->listenQTail + 1) % MAXLISTEN; \
	} else \
		(ntcb) = NULL; \
}


/******************************/
/*** PUBLIC DATA STRUCTURES ***/
/******************************/

#if STATS_SUPPORT > 0
TCPStats tcpStats;
#endif


/*****************************/
/*** LOCAL DATA STRUCTURES ***/
/*****************************/
/*
 * TCP Control block free list. 
 */
TCPCB tcbs[MAXTCP];
TCPCB *topTcpCB;					/* Ptr to top TCB on free list. */
TCPCB *tcbTbl[NTCB];				/* Hash table for lookup. */

u_int16_t tcpFreePort = TCP_DEFPORT;	/* Initial local port. */

u_int32_t newISNOffset;					/* Offset for the next sequence number. */


/* TCB state labels for debugging. */
char *tcbStates[] = {
	"CLOSED",
	"LISTEN",
	"SYN_SENT",
	"SYN_RECEIVED",
	"ESTABLISHED",
	"FINWAIT1",
	"FINWAIT2",
	"CLOSE_WAIT",
	"CLOSING",
	"LAST_ACK",
	"TIME_WAIT"
};

/* TCP Header Flag labels. */
#define TCPFLAGLABELMASK 0x1F		/* We don't display URGENT. */
const char *tcpFlagLabel[] = {
	"NONE",						/* 0 */
	"FIN",						/* 1 */
	"SYN",						/* 2 */
	"SYN+FIN",					/* 3 = 2 + 1 */
	"RST",						/* 4 */
	"RST+FIN",					/* 5 = 4 + 1 */
	"RST+SYN",					/* 6 = 4 + 2 */
	"RST+S+F",					/* 7 = 4 + 2 + 1 */
	"PUSH",						/* 8 */
	"PUSH+FIN",					/* 9 = 8 + 1 */
	"PUSH+SYN",					/* 10 = 8 + 2 */
	"PUSH+S+F",					/* 11 = 8 + 2 + 1 */
	"PUSH+RST",					/* 12 = 8 + 4 */
	"PUSH+R+F",					/* 13 = 8 + 4 + 1 */
	"PUSH+R+S",					/* 14 = 8 + 4 + 2 */
	"PUSH+R+S+F",				/* 15 = 8 + 4 + 2 + 1 */
	"ACK",						/* 16 */
	"ACK+FIN",					/* 17 = 16 + 1 */
	"ACK+SYN",					/* 18 = 16 + 2 */
	"ACK+S+F",					/* 19 = 16 + 2 + 1 */
	"ACK+RST",					/* 20 = 16 + 4 */
	"ACK+R+F",					/* 21 = 16 + 4 + 1 */
	"ACK+R+S",					/* 22 = 16 + 4 + 2 */
	"ACK+R+S+F",				/* 23 = 16 + 4 + 2 + 1 */
	"ACK+PUSH",					/* 24 = 16 + 8 */
	"ACK+P+F",					/* 25 = 16 + 8 + 1 */
	"ACK+P+S",					/* 26 = 16 + 8 + 2 */
	"ACK+P+S+F",				/* 27 = 16 + 8 + 2 + 1 */
	"ACK+P+R",					/* 28 = 16 + 8 + 4 */
	"A+P+R+F",					/* 29 = 16 + 8 + 4 + 1 */
	"A+P+R+S",					/* 30 = 16 + 8 + 4 + 2 */
	"A+P+R+S+F"					/* 31 = 16 + 8 + 4 + 2 + 1 */
};

char tcpEchoStack[STACK_SIZE];			/* The TCP echo task stack. */


/***********************************/
/*** PUBLIC FUNCTION DEFINITIONS ***/
/***********************************/
/*
 * Initialize the TCP subsystem.
 */
void tcpInit(void)
{
	int i;
	
	/* The TCB free list. */
	memset(tcbs, 0, sizeof(tcbs));
	topTcpCB = &tcbs[0];
	for (i = 0; i < MAXTCP; i++) {
		tcbs[i].next = &tcbs[i + 1];
		/* Prev referencing self indicates that it's on the free list. */
		tcbs[i].prev = &tcbs[i];
		timerCreate(&tcbs[i].resendTimer);
		timerCreate(&tcbs[i].keepTimer);
		tcbs[i].state = CLOSED;
	}
	tcbs[MAXTCP - 1].next = NULL;

	/* The TCB hash table. */
	memset(&tcbTbl, 0, sizeof(tcbTbl));
	
	/* The TCP stats. */
#if STATS_SUPPORT > 0
	memset(&tcpStats, 0, sizeof(tcpStats));
	tcpStats.headLine.fmtStr	= "\t\tTCP STATISTICS\r\n";
	tcpStats.curFree.fmtStr		= "\tCURRENT FREE: %5lu\r\n";
	tcpStats.curFree.val		= MAXTCP;
	tcpStats.minFree.fmtStr		= "\tMINIMUM FREE: %5lu\r\n";
	tcpStats.minFree.val		= MAXTCP;
	tcpStats.runt.fmtStr		= "\tRUNT HEADERS: %5lu\r\n";
	tcpStats.checksum.fmtStr	= "\tBAD CHECKSUM: %5lu\r\n";
	tcpStats.conout.fmtStr		= "\tOUT CONNECTS: %5lu\r\n";
	tcpStats.conin.fmtStr		= "\tIN CONNECTS : %5lu\r\n";
	tcpStats.resetOut.fmtStr	= "\tRESETS SENT : %5lu\r\n";
	tcpStats.resetIn.fmtStr		= "\tRESETS REC'D: %5lu\r\n";
#endif
	
	/* The new sequence number offset. */
	newISNOffset = magic();
	
#if ECHO_SUPPORT > 0
	/* Start the TCP echo server. */
	OSTaskCreate(tcpEcho, NULL, tcpEchoStack + STACK_SIZE, PRI_ECHO);
#endif
	
}

/* 
 * Return a new TCP descriptor on success or an error code (negative) on 
 *	failure. 
 */
int tcpOpen(void)
{
	int st;
	TCPCB *tcb;
	
	OS_ENTER_CRITICAL();
	if ((tcb = topTcpCB) != NULL) {
		topTcpCB = topTcpCB->next;
		STATS(if (--tcpStats.curFree.val < tcpStats.minFree.val)
				tcpStats.minFree.val = tcpStats.curFree.val;)
	}
	OS_EXIT_CRITICAL();
	
	if (!tcb)
		st = TCPERR_ALLOC;
	else {
		st = (int)(tcb - &tcbs[0]);
		tcb->next = tcb;		/* Self ref => unlinked. */
		tcb->prev = NULL;		/* Always NULL when neither free nor linked. */
		
		tcb->freeOnClose = 0;
		tcb->traceLevel = LOG_INFO;
		tcb->keepAlive = 0;
		tcb->keepProbes = 0;
		
		/* Grab semaphores. */
		if (!tcb->connectSem)
			if ((tcb->connectSem = OSSemCreate(0)) == NULL)
				st = TCPERR_ALLOC;
		if (!tcb->readSem)
			if ((tcb->readSem = OSSemCreate(0)) == NULL)
				st = TCPERR_ALLOC;
		if (!tcb->writeSem)
			if ((tcb->writeSem = OSSemCreate(0)) == NULL)
				st = TCPERR_ALLOC;
		if (!tcb->mutex)
			if ((tcb->mutex = OSSemCreate(1)) == NULL)
				st = TCPERR_ALLOC;
		TCPDEBUG((tcb->traceLevel, TL_TCP, "tcpOpen[%d]: Opened", st));
	}
	
	return st;
}

/* 
 * Close a TCP connection and release the descriptor.
 * Any outstanding packets in the queues are dropped.
 * Return 0 on success when the peer acknowledges our message
 * or an error code on failure. 
 */
int tcpClose(u_int td)
{
	int st = 0;
	TCPCB *tcb = &tcbs[td];

	/* Protect from race on tcb->state. */
	OS_ENTER_CRITICAL();	
	if (td >= MAXTCP || tcb->prev == tcb) {
		OS_EXIT_CRITICAL();
		st = TCPERR_PARAM;

	} else if (tcb->state == CLOSED) {
		OS_EXIT_CRITICAL();
		TCPDEBUG((tcb->traceLevel, TL_TCP, "tcpClose[%d]: Freeing closed", td));
		tcbFree(tcb);
		
	} else {
		/* 
		 * Initiate a half-close on our side by sending a FIN.  The
		 * freeOnClose flag is set so the TCB will be freed when the
		 * state reaches CLOSED.  Note that a timer will limit the
		 * time that we wait in FINWAIT2.
		 */
		tcb->freeOnClose = !0;
		OS_EXIT_CRITICAL();
		
		st = tcpDisconnect(td);
		TCPDEBUG((tcb->traceLevel, TL_TCP, "tcpClose[%d]: Closed", td));
	}	
	return st;
}

/*
 * Bind an IP address and port number in the sockaddr structure as our
 * address on a TCP connection.
 * Note: The IP address must be zero (wild) or equal to localHost since that
 * is all that ipDispatch() will recognize.  You can only bind a CLOSED
 * connection.
 * Return 0 on success, an error code on failure.
 */
int tcpBind(u_int td, struct sockaddr_in *myAddr)
{
	int st = 0;
	TCPCB *tcb = &tcbs[td];
	
	if (td >= MAXTCP || tcb->prev == tcb || !myAddr)
		st = TCPERR_PARAM;
	else if (myAddr->ipAddr != 0 && myAddr->ipAddr != localHost)
		st = TCPERR_INVADDR;
	else if (tcb->state != CLOSED)
		st = TCPERR_CONNECT;	/* Can't bind an active connection. */
	else {
		tcb->ipSrcAddr = htonl(myAddr->ipAddr);
		tcb->tcpSrcPort = htons(myAddr->sin_port);

		TCPDEBUG((tcb->traceLevel, TL_TCP, "tcpBind[%d]: to %s:%u mss %d", 
					(int)(tcb - &tcbs[0]),
					ip_ntoa(tcb->ipSrcAddr), ntohs(tcb->tcpSrcPort),
					tcb->mss));
	}
	
	return st;
}

/*
 * Establish a connection with a remote host.  Unless tcpBind() has been called,
 * the local IP address and port number are generated automatically.
 * Return 0 on success, an error code on failure.
 */
int tcpConnectJiffy(u_int td, const struct sockaddr_in *remoteAddr, u_char tos, u_int timeout)
{
	int st = 0;
	TCPCB *tcb = &tcbs[td];
	u_long abortTime;
	long dTime = timeout;
	
	if (timeout)
		abortTime = jiffyTime() + timeout;
		
	if (td >= MAXTCP || tcb->prev == tcb || !remoteAddr)
		st = TCPERR_PARAM;
	else if (remoteAddr->ipAddr == 0 || remoteAddr->sin_port == 0)
		st = TCPERR_INVADDR;
	else if (tcb->ipSrcAddr == 0 && localHost == 0)
		st = TCPERR_CONFIG;
	else if (tcb->state != CLOSED)
		st = TCPERR_CONNECT;	/* Already connected! */
	else {
		tcbInit(tcb);
		tcb->ipTOS = tos;
		if (tcb->ipSrcAddr == 0)
			tcb->ipSrcAddr = htonl(localHost);
		if (tcb->tcpSrcPort == 0) {
			OS_ENTER_CRITICAL();
			tcb->tcpSrcPort = htons(tcpFreePort++);
			OS_EXIT_CRITICAL();
		}
		tcb->ipDstAddr = htonl(remoteAddr->ipAddr);
		tcb->tcpDstPort = htons(remoteAddr->sin_port);

		/* Initialize connection parameters. */		
		tcb->rcv.wnd = TCP_DEFWND;
		tcb->mss = ipMTU(tcb->ipDstAddr) - sizeof(IPHdr) - sizeof(TCPHdr);
		tcb->mss = MAX(tcb->mss, TCP_MINMSS);
		tcb->minFreeBufs = ((tcb->mss + NBUFSZ) / NBUFSZ);

		/* 
		 * Load the connection structure and link the TCB into the connection
		 * table so that tcpInput can find it.
		 */
		tcb->conn.remoteIPAddr = tcb->ipDstAddr;
		tcb->conn.remotePort = tcb->tcpDstPort;
		tcb->conn.localIPAddr = tcb->ipSrcAddr;
		tcb->conn.localPort = tcb->tcpSrcPort;
		tcbLink(tcb);
		
		TCPDEBUG((tcb->traceLevel, TL_TCP, "tcpConnect[%d]: to %s:%u mss %d", 
					(int)(tcb - &tcbs[0]),
					ip_ntoa(tcb->ipDstAddr), ntohs(tcb->tcpDstPort),
					tcb->mss));
		
		/* Send SYN, go into SYN_SENT state */
		tcb->flags |= ACTIVE;
		sendSyn(tcb);
		setState(tcb, SYN_SENT);
		tcpOutput(tcb);
		STATS(tcpStats.conout.val++;)
		
		/* Wait for connection or failure. */
		while(tcb->state != ESTABLISHED && !st) {
			if (tcb->state == CLOSED) {
				/* 
				 * Post the connect semaphore in case another task was also
				 * waiting on it.  Unlikely for connect but a single extra
				 * post costs little and improves robustness.
				 */
				OSSemPost(tcb->connectSem);
				if (tcb->closeReason)
					st = tcb->closeReason;
				else
				    st = TCPERR_EOF;
			} else if (!timeout || (dTime = diffJTime(abortTime)) > 0) {
				OSSemPend(tcb->connectSem, (UINT)dTime);
			} else {					/* Abort on timeout. */
				closeSelf(tcb, TCPERR_TIMEOUT);
				tcbUnlink(tcb);
			}
		}
	}
			
	TCPDEBUG((tcb->traceLevel, TL_TCP, "tcpConnect[%d]: %s", 
				(int)(tcb - &tcbs[0]), tcbStates[tcb->state]));
	
	return st;
}

/*
 * tcpDisconnect - Tell the peer that we will not be sending any more data
 * (i.e. perform a half close on a connection).  tcpRead() will then
 * wait until the connection closes.
 * Return 0 when the peer acknowledges our message or an error code on
 * failure.
 */
int tcpDisconnect(u_int td)
{
	int st = 0;
	TCPCB *tcb = &tcbs[td];
	
	TCPDEBUG((tcb->traceLevel, TL_TCP, "tcpDisconnect[%d]: state %s", 
				(int)(tcb - &tcbs[0]), tcbStates[tcb->state]));
					
	if (td >= MAXTCP || tcb->prev == tcb)
		st = TCPERR_PARAM;
		
	else {
		switch(tcb->state){
		case LISTEN:
		case SYN_SENT:
			/*
			 * We haven't established a connection yet so we can just
			 * close this.
			 */
			closeSelf(tcb, 0);
			break;
			
		case SYN_RECEIVED:
		case ESTABLISHED:
			/* 
			 * Initiate a half-close on our side by sending a FIN.
			 * Our FIN is indicated by setting sndcnt to the number of bytes in
			 * the output queue + 1. 
			 */
			tcb->sndcnt++;
			tcb->snd.nxt++;
			setState(tcb, FINWAIT1);
			tcpOutput(tcb);
			break;
			
		case CLOSE_WAIT:
			/* 
			 * The peer has initiated a half-close.  We'll ACK it and complete
			 * the close by sending a FIN and waiting for it to be acknowledged.
			 * Our FIN is indicated by setting sndcnt to the number of bytes in
			 * the output queue + 1. 
			 */
			tcb->sndcnt++;
			tcb->snd.nxt++;
			setState(tcb, LAST_ACK);
			tcpOutput(tcb);
			break;
			
		case FINWAIT1:
		case FINWAIT2:
		case LAST_ACK:
		case CLOSING:
		case TIME_WAIT:
			/* Do nothing - we're already closing! */
			break;
		
		case CLOSED:
			/* Nothing to do! */
			break;
		}
	}	
	return st;
}

/*
 * Set the number of backLog connections which will be queued to be picked up
 * by calls to accept.  Without this call, no connection will be opened until
 * tcpAccept() or tcpConnect() is called.
 * Return the actual size of the queue on success, an error code on failure.
 */
int tcpListen(u_int td, int backLog)
{
	int st = 0;
	TCPCB *tcb = &tcbs[td];
	
	if (td >= MAXTCP || tcb->prev == tcb)
		st = TCPERR_PARAM;
		
	else if (tcb->tcpSrcPort == 0)
		st = TCPERR_CONFIG;
		
	else {
		switch(tcb->state){
		case CLOSED:
			tcbInit(tcb);
			tcb->conn.localIPAddr = tcb->ipSrcAddr;
			tcb->conn.localPort = tcb->tcpSrcPort;
			/* XXX Do we want 0 or left over address? */
			tcb->conn.remoteIPAddr = 0;
			tcb->conn.remotePort = 0;
			tcbLink(tcb);
			setState(tcb, LISTEN);
			/* Fall through... */
		case LISTEN:
			st = tcb->listenQOpen = MIN(backLog, MAXLISTEN);
			tcb->flags |= CLONE;
			
			TCPDEBUG((tcb->traceLevel, TL_TCP, "tcpListen[%d]: %s:%u #%u", 
						(int)(tcb - &tcbs[0]),
						ip_ntoa(tcb->ipSrcAddr), tcb->tcpSrcPort,
						tcb->listenQOpen));
			break;
		case SYN_SENT:
		case SYN_RECEIVED:
		case ESTABLISHED:
		case CLOSE_WAIT:
		case FINWAIT1:
		case FINWAIT2:
		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
			st = TCPERR_CONNECT;
			break;
		}
	}	
	
	TCPDEBUG((tcb->traceLevel, TL_TCP, "tcpListen[%d]: %s => %d", 
				(int)(tcb - &tcbs[0]), tcbStates[tcb->state], st));
					
	return st;
}

/*
 * Pick up a connection opened by a remote host.  tcpBind() must be used to
 * specify the local address (possibly zero) and port number (non-zero) for
 * the connection.  Unless tcpListen() has been called, no connection will
 * be accepted until this is called.
 * Return a new TCP descriptor for the opened connection on success, an
 * error code on failure.  The peer's IP and port values are returned
 * in peerAddr.
 */
#pragma argsused
int tcpAcceptJiffy(u_int td, struct sockaddr_in *peerAddr, u_int timeout)
{
	int st = 0;
	TCPCB *ntcb = NULL;
	TCPCB *tcb = &tcbs[td];
	u_long abortTime;
	long dTime = timeout;
	
	TCPDEBUG((tcb->traceLevel, TL_TCP, "tcpAccept[%d]: accepting %s:%u", 
				(int)(tcb - &tcbs[0]),
				ip_ntoa(tcb->ipSrcAddr), ntohs(tcb->tcpSrcPort)));
					
	if (timeout)
		abortTime = jiffyTime() + timeout;
		
	if (td >= MAXTCP || tcb->prev == tcb)
		st = TCPERR_PARAM;
		
	else if (tcb->tcpSrcPort == 0)
		st = TCPERR_CONFIG;
		
	else {
		switch(tcb->state){
		case CLOSED:
			tcbInit(tcb);
			tcb->conn.localIPAddr = tcb->ipSrcAddr;
			tcb->conn.localPort = tcb->tcpSrcPort;
			/* XXX Do we want 0 or whatever's in peerAddr? */
			tcb->conn.remoteIPAddr = 0;
			tcb->conn.remotePort = 0;
			tcbLink(tcb);
			setState(tcb, LISTEN);
			/* Fall through... */
		case LISTEN:
			if (tcb->flags & CLONE) {
				OS_ENTER_CRITICAL();
				while(!ntcb && !st) {
					if (tcb->state != LISTEN) {
						st = TCPERR_CONNECT;
					} else if (!listenQEmpty(tcb)) {
						listenQPop(tcb, &ntcb);
					} else {
						OS_EXIT_CRITICAL();
						if (!timeout || (dTime = diffJTime(abortTime)) > 0)
							OSSemPend(tcb->connectSem, (UINT)dTime);
						else
							st = TCPERR_TIMEOUT;		/* Abort on timeout. */
						OS_ENTER_CRITICAL();
					} 
				}
				OS_EXIT_CRITICAL();
			} else {
				while(CLOSED < tcb->state && tcb->state < ESTABLISHED) {
					if (!timeout || (dTime = diffJTime(abortTime)) > 0)
						OSSemPend(tcb->connectSem, (UINT)dTime);
					else {
						closeSelf(tcb, TCPERR_TIMEOUT);
						tcbUnlink(tcb);
					}
				}
				if (tcb->state == ESTABLISHED)
					ntcb = tcb;
				else if (tcb->closeReason)
					st = tcb->closeReason;
				else
					st = TCPERR_CONNECT;
			}
			if (!st) {
				ntcb->flags &= ~CLONE;
				peerAddr->ipAddr = ntohl(tcb->ipDstAddr);
				peerAddr->sin_port = ntohs(tcb->tcpDstPort);
				st = (int)(ntcb - &tcbs[0]);
				TCPDEBUG((tcb->traceLevel, TL_TCP, "tcpAccept[%d]: %s:%u", 
							(int)(tcb - &tcbs[0]),
							ip_ntoa(tcb->ipDstAddr), ntohs(tcb->tcpDstPort)));
			} else {
				TCPDEBUG((tcb->traceLevel, TL_TCP, "tcpAccept[%d]: at %s => %d", 
							(int)(tcb - &tcbs[0]), tcbStates[tcb->state], st));
			}
			break;
		case SYN_SENT:
		case SYN_RECEIVED:
		case ESTABLISHED:
		case CLOSE_WAIT:
		case FINWAIT1:
		case FINWAIT2:
		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
			st = TCPERR_CONNECT;
			break;
		}
	}	
	return st;
}

/*
 * Read from a connected TCP connection.  If a timeout is non-zero, we block 
 *	until the requested data is received or the timeout expires.  Otherwise
 *	we block only until at least one byte has been received or an error
 *	occurs.
 * Note: Ideally we would return less than len bytes only if a PUSH flag
 *	was received however this is yet to be implemented.
 * Return the number of bytes read on success, an error code on failure. 
 */
int tcpRead(u_int td, void *s, u_int len)
{
	return tcpReadJiffy(td, s, len, 0);
}
int tcpReadJiffy(u_int td, void *s1, u_int len, u_int timeout)
{
	char *s = (char*)s1;
	TCPCB *tcb = &tcbs[td];
	u_long abortTime;
	long dTime = timeout;
	u_int i;
	int st = 0;

	if (timeout)
		abortTime = jiffyTime() + timeout;
		
	if (td >= MAXTCP || tcb->prev == tcb)
		st = TCPERR_PARAM;
		
	else if (tcb->state == CLOSED
				|| tcb->ipSrcAddr == 0
				|| tcb->tcpSrcPort == 0
				|| tcb->ipDstAddr == 0
				|| tcb->tcpDstPort == 0)
		st = TCPERR_CONNECT;
	
	/*
	 * Loop here until either we have received something, hit a snag, or had
	 *	our connection closed.
	 */
	else while (len) {
		/* If there's something in the receive buffer, start with that. */
		if (tcb->rcvBuf) {
			i = nTrim(s, &tcb->rcvBuf, len);
			TCPDEBUG((tcb->traceLevel + 1, TL_TCP, "tcpRead[%d]: %u:%.*H",
						td, i, min(60, i * 2), s));
			st += i;
			len -= i;
			s += i;
			
			OS_ENTER_CRITICAL();
			tcb->rcvcnt -= i;
			OS_EXIT_CRITICAL();

		/* 
		 * If there's something in the receive queue, dequeue the next segment. 
		 * If successful, adjust our receive window.
		 */
		} else if (tcb->rcvcnt != 0) {
			nDEQUEUE(&tcb->rcvq, tcb->rcvBuf);
			if (tcb->rcvBuf) {
				OS_ENTER_CRITICAL();
				i = tcb->rcv.wnd;
				/* 
				 * Since we queue buffer chains and not characters, the receive
				 * window is adjusted by multiples of buffer lengths.
				 *
				 * XXX Here we assume that normally each buffer chain is of
				 * length 1.  If this is not the case, it may be better to
				 * adjust the buffer size rather than complicate this.  Only
				 * if you want to support greatly varying segment sizes would
				 * it be worth tracking the number of buffers in each chain.
				 */
				if ((tcb->rcv.wnd += NBUFSZ) > TCP_DEFWND)
					tcb->rcv.wnd = TCP_DEFWND;
				/* Do a window update if it was closed. */
				if (i == 0) {
					tcb->flags |= FORCE;
					OS_EXIT_CRITICAL();
					
					tcpOutput(tcb);
				} else {
					OS_EXIT_CRITICAL();
				}
			}
		
		/*
		 * We've emptied the receive queue.  If we've copied something and
		 *	there's no timeout, let's return what we've got rather than 
		 *	waiting for more.
		 *
		 * XXX We should only exit here if a PUSH segment was received.
		 */
		} else if (st && !timeout)
			len = 0;
		
		/*
		 * If we're expecting something to come in, wait for it.  Otherwise,
		 * return EOF.
		 */
		else switch(tcb->state) {
		case LISTEN:
		case SYN_SENT:
		case SYN_RECEIVED:
		case ESTABLISHED:
		case FINWAIT1:
		case FINWAIT2:
			if (!timeout || (dTime = diffJTime(abortTime)) > 0)
				OSSemPend(tcb->readSem, (UINT)dTime);
			else
				len = 0;		/* Abort on timeout. */
			break;
		case CLOSED:
		case CLOSE_WAIT:
		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
			if (tcb->closeReason)
				st = tcb->closeReason;
			else
				st = TCPERR_EOF;
			len = 0;
		    break;
		}
	}
	
	return st;
}

/*
 * Write to a connected TCP connection.  This blocks until either all bytes
 *	are queued, the timeout is reached, or an error occurs.
 * Return the number of bytes written on success, an error code on failure.
 */
int tcpWrite(u_int td, const void *s, u_int len)
{
	return tcpWriteJiffy(td, s, len, 0);
}
int tcpWriteJiffy(u_int td, const void *s1, u_int len, u_int timeout)
{
	const char *s = (char*)s1;
	TCPCB *tcb = &tcbs[td];
	NBuf *outBuf = NULL;
	u_long abortTime;
	long dTime = timeout;
	u_int segSize;
	int sendSize;
	int st = 0;

	if (timeout)
		abortTime = jiffyTime() + timeout;
		
	if (td >= MAXTCP || tcb->prev == tcb)
		st = TCPERR_PARAM;
		
	else if (tcb->state == CLOSED
				|| tcb->ipSrcAddr == 0
				|| tcb->tcpSrcPort == 0
				|| tcb->ipDstAddr == 0
				|| tcb->tcpDstPort == 0) {
		st = TCPERR_CONNECT;
	}
	
	/*
	 * Loop here until either we have queued our data, hit a snag, had
	 * our connection closed, or timed out.
	 */
	else while (len) {
		/* 
		 * Wait for space in the queue to queue up what we've got up to
		 * a full length segment. 
		 */
		OS_ENTER_CRITICAL();
		sendSize = tcb->snd.wnd - tcb->sndcnt;
		OS_EXIT_CRITICAL();
		sendSize = MIN(sendSize, len);
		sendSize = MIN(sendSize, tcb->mss);
		
		/*
		 * Block if we can't send anything or if we've got our quota of 
		 * outstanding segments already in the queue.  It's up to the
		 * input side to wake us up when things open up.
		 */
		if (sendSize <= 0 || tcb->sndq.qLen >= TCP_MAXQUEUE) {
			if (!timeout || (dTime = diffJTime(abortTime)) > 0)
				OSSemPend(tcb->writeSem, (UINT)dTime);
			else
				len = 0;		/* Abort on timeout. */
			
		/* 
		 * Get a network buffer to fill.  Ensure that enough buffers remain
		 * on the free list to enable receiving an acknowledgement on a full
		 * length segment.
		 * If we fail, poll for free buffers until we get one or we time out.
		 */
		} else if (!outBuf) {
			if (nBUFSFREE() < tcb->minFreeBufs + (sendSize / NBUFSZ) * 2) {
				if (!timeout || (dTime = diffJTime(abortTime)) > 0)
					OSSemPend(tcb->writeSem, MIN((UINT)dTime, WRITESLEEP));
				else
					len = 0;		/* Abort on timeout. */
					
			} else {
				nGET(outBuf);
			}
			/* Loop again and update the open size. */
		
		/*
		 * Prepare and queue whatever we can.
		 */
		} else {
			nAPPEND(outBuf, s, sendSize, segSize);
			if (segSize > 0) {
				TCPDEBUG((tcb->traceLevel + 1, TL_TCP, "tcpWrite[%d]: %u:%.*H",
							td, segSize, min(60, segSize * 2), s));
				len -= segSize;
				s += segSize;
				switch(tcb->state) {
				case SYN_SENT:
				case SYN_RECEIVED:
				case ESTABLISHED:
				case CLOSE_WAIT:
					OSSemPend(tcb->mutex, 0);
					nENQUEUE(&tcb->sndq, outBuf);
					OSSemPost(tcb->mutex);
					outBuf = NULL;
					st += segSize;
					
					OS_ENTER_CRITICAL();
					tcb->sndcnt += segSize;
					OS_EXIT_CRITICAL();
					
					tcpOutput(tcb);
					break;
				case LISTEN:
				case FINWAIT1:
				case FINWAIT2:
				case CLOSING:
				case LAST_ACK:
				case TIME_WAIT:
				case CLOSED:
					nFreeChain(outBuf);
					len = 0;
					if (tcb->closeReason)
						st = tcb->closeReason;
					else
					    st = TCPERR_EOF;
					break;
				}
			}
		}
	}
	
	return st;
}


/*
 * tcpWait - Wait for the connection to be closed.  Normally this will be
 * done after a disconnect before trying to reuse the TCB.  This will fail
 * if the connection is not closing.
 * Returns 0 on success or an error code if the connection is not
 * closing.
 */
int tcpWait(u_int td)
{
	TCPCB *tcb = &tcbs[td];
	int st = 0;

	/* Here we allow the TCB to be on the free list. */
	if (td >= MAXTCP)
		st = TCPERR_PARAM;
		
	else if (tcb->state != CLOSED && tcb->state < FINWAIT1)
		st = TCPERR_CONNECT;
	
	else while (tcb->state != CLOSED)
		OSSemPend(tcb->connectSem, 0);
	
	return st;
}


/* 
 * Receive an incoming datagram.  This is called from IP with the IP and
 * TCP headers intact at the head of the buffer chain.
 */
void tcpInput(NBuf *inBuf, u_int ipHeadLen)
{
	
	TCPCB *tcb;
	Connection conn;
	u_int tcpHeadLen;			/* Length of TCP header. */
	int  segLen;				/* TCP segment length exclusive of flags. */
	IPHdr *ipHdr;				/* Ptr to IP header in output buffer. */
	TCPHdr *tcpHdr;				/* Ptr to TCP header in output buffer. */
	
	u_int chkSum;
	static chkFail = 0;
	
	if (inBuf == NULL) {
		TCPDEBUG((LOG_ERR, TL_TCP, "tcpInput: Null input dropped"));
		return;
	}

	/*
	 * Strip off the IP options.  The TCP checksum includes fields from the
	 * IP header but without the options.
	 */
	if (ipHeadLen > sizeof(IPHdr)) {
		inBuf = ipOptStrip(inBuf, ipHeadLen);
		ipHeadLen = sizeof(IPHdr);
	}
	
	/*
	 * Get IP and TCP header together in first nBuf.
	 */
	if (inBuf->len < sizeof(TCPHdr) + sizeof(IPHdr)) {
		if ((inBuf = nPullup(inBuf, sizeof(TCPHdr) + ipHeadLen)) == 0) {
			STATS(tcpStats.runt.val++;)
			TCPDEBUG((LOG_ERR, TL_TCP, "tcpInput: Runt packet dropped"));
#if DEBUG_SUPPORT > 0
			nDumpChain(inBuf);
#endif
			return;
		}
	}
	ipHdr = nBUFTOPTR(inBuf, IPHdr *);
	/*
	 * Note: We use ipHeadLen below just in case we kept an option with
	 *	the IP header.
	 */
	tcpHdr = (TCPHdr *)((char *)ipHdr + ipHeadLen);

	/*
	 * Prepare the header for the TCP checksum.  The TCP checksum is
	 * computed on a pseudo IP header as well as the TCP header and
	 * the data segment.  The pseudo IP header includes the length
	 * (not including the length of the IP header), protocol, source
	 * address and destination address fields.  We prepare this by
	 * clearing the TTL field and loading the length in the IP checksum
	 * field.
	 */
	ipHdr->ip_ttl = 0;
	ipHdr->ip_sum = htons(ipHdr->ip_len - sizeof(IPHdr));
	
	/* Validate the TCP checksum including fields from IP TTL. */
	if ((chkSum = inChkSum(inBuf, ipHdr->ip_len - 8, 8)) != 0) {
		/* Checksum failed, ignore segment completely */
		STATS(tcpStats.checksum.val++;)
		TCPDEBUG((LOG_ERR, TL_TCP, "tcpInput: Bad checksum %X", chkSum));
#if DEBUG_SUPPORT > 0
		nDumpChain(inBuf);
#endif
		if (++chkFail > 3) {
			/* Break point. */
			TCPDEBUG((LOG_ERR, TL_TCP, "tcpInput: Serious checksum issue here."));
		}
		nFreeChain(inBuf);
		return;
	}

	/* Convert needed TCP fields to host byte order. */
	if ((tcpHeadLen = tcpHdr->tcpOff * 4) < sizeof(TCPHdr)) {
		/* TCP header is too small */
		STATS(tcpStats.runt.val++;)
		TCPDEBUG((LOG_ERR, TL_TCP, "tcpInput: Bad TCP header len %u", tcpHeadLen));
#if DEBUG_SUPPORT > 0
		nDumpChain(inBuf);
#endif
		nFreeChain(inBuf);
		return;
	}
	NTOHL(tcpHdr->seq);
	NTOHL(tcpHdr->ack);
	NTOHS(tcpHdr->win);
	NTOHS(tcpHdr->urgent);

	segLen = ipHdr->ip_len - sizeof(IPHdr) - tcpHeadLen;

	/* Find the connection if any. */	
	conn.localIPAddr = ipHdr->ip_dst.s_addr;
	conn.localPort = tcpHdr->dstPort;
	conn.remoteIPAddr = ipHdr->ip_src.s_addr;
	conn.remotePort = tcpHdr->srcPort;
	if((tcb = tcbLookup(&conn)) == NULL) {
		TCPCB *ntcb;
		
		if(!(tcpHdr->flags & TH_SYN)) {
			/* No open TCB for this connection so reject */
			tcpReset(inBuf, ipHdr, tcpHdr, segLen);
			return;
		}
		
		/*
		 * Check for a LISTEN on this connection request.
		 */
		conn.remoteIPAddr = 0;
		conn.remotePort = 0;
		if((tcb = tcbLookup(&conn)) == NULL) {
			/*
			 * Could be a LISTEN with a null local address.
			 */
			conn.localIPAddr = 0;
			if((tcb = tcbLookup(&conn)) == NULL) {
				/* No unspecified LISTEN so reject */
				tcpReset(inBuf, ipHdr, tcpHdr, segLen);
				return;
			}
		}
		/* We've found a server listen socket, so clone the TCB */
		if(tcb->flags & CLONE) {
			OS_EVENT *connectSem;	/* Semaphore for connections. */
			OS_EVENT *readSem;		/* Semaphore for read function. */
			OS_EVENT *writeSem;		/* Semaphore for write function. */
			OS_EVENT *mutex;		/* Semaphore for mutex. */
			
			/*
			 * If no room in the listen queue, we have to reject the connection. 
			 */
			if (tcb->listenQOpen < listenQLen(tcb)) {
				tcpReset(inBuf, ipHdr, tcpHdr, segLen);
				return;
			}
		
			/* Get a free TCB. */
			OS_ENTER_CRITICAL();
			if ((ntcb = topTcpCB) == NULL) {
				OS_EXIT_CRITICAL();
				
				/* This may fail, but we should at least try */
				tcpReset(inBuf, ipHdr, tcpHdr, segLen);
				return;
			} else {
				topTcpCB = topTcpCB->next;
				ntcb->next = ntcb;	/* Next -> self => neither free nor linked. */
				ntcb->prev = NULL;	/* Always NULL when neither free nor linked. */
				STATS(if (--tcpStats.curFree.val < tcpStats.minFree.val)
						tcpStats.minFree.val = tcpStats.curFree.val;)
				OS_EXIT_CRITICAL();
			}
			
			/* Duplicate the TCB but must preserve the semaphores. */
			connectSem = ntcb->connectSem;
			readSem = ntcb->readSem;
			writeSem = ntcb->writeSem;
			mutex = ntcb->mutex;
			memcpy(ntcb, tcb, sizeof(TCPCB));
			ntcb->connectSem = connectSem;
			ntcb->readSem = readSem;
			ntcb->writeSem = writeSem;
			ntcb->mutex = mutex;

			/* 
			 * Put this on the parent's accept queue.
			 */
			listenQPush(tcb, ntcb);
			
			tcb = ntcb;
			
		/* Otherwise we use the original TCB. */
		} else {
			tcbUnlink(tcb);	/* It'll be put back on later */
		}

		/* Load the local address and remote address and port into the TCB. */
		tcb->ipSrcAddr = tcb->conn.localIPAddr = ipHdr->ip_dst.s_addr;
		tcb->ipDstAddr = tcb->conn.remoteIPAddr = ipHdr->ip_src.s_addr;
		tcb->tcpDstPort = tcb->conn.remotePort = tcpHdr->srcPort;

		/* Initialize connection parameters. */		
		tcb->rcv.wnd = TCP_DEFWND;
		tcb->mss = ipMTU(tcb->ipDstAddr) - sizeof(IPHdr) - sizeof(TCPHdr);
		tcb->mss = MAX(tcb->mss, TCP_MINMSS);
		tcb->minFreeBufs = ((tcb->mss + NBUFSZ) / NBUFSZ);

		/* NOW put it on the right hash chain */
		tcbLink(tcb);
	}
	
	TCPDEBUG((tcb->traceLevel, TL_TCP, "tcpInput[%d]: %s:%u->%s:%u %d@%lu",
				(int)(tcb - & tcbs[0]),
				ip_ntoa2(ipHdr->ip_src.s_addr), ntohs(tcpHdr->srcPort),
				ip_ntoa(ipHdr->ip_dst.s_addr), ntohs(tcpHdr->dstPort),
				segLen, tcpHdr->seq));
	TCPDEBUG((tcb->traceLevel, TL_TCP, "               %s %lu win %u",
				tcpFlagLabel[tcpHdr->flags & TCPFLAGLABELMASK],
				tcpHdr->ack, tcpHdr->win));
	TCPDEBUG((tcb->traceLevel + 2, TL_TCP, "          IP: %.*H", 
				ipHeadLen * 2, (char *)ipHdr));
	TCPDEBUG((tcb->traceLevel + 2, TL_TCP, "         TCP: %.*H", 
				tcpHeadLen * 2, (char *)tcpHdr));
	if (segLen > 0) {
		if (tcpHeadLen + sizeof(IPHdr) < inBuf->len) {
			TCPDEBUG((tcb->traceLevel, TL_TCP, "        DATA: %.*H",
						MIN(segLen, 20) * 2, (char *)tcpHdr + tcpHeadLen));
		} else if (inBuf->nextBuf) {
			NBuf *n0 = inBuf->nextBuf;
			TCPDEBUG((tcb->traceLevel, TL_TCP, "        DATA: %.*H",
						MIN(segLen, 20) * 2, nBUFTOPTR(n0, char *)));
		}
	}
				
	/*
	 * If we're doing keep alive, update the keep alive timer.
	 */
	if (tcb->keepAlive) {
		tcb->keepTime = OSTimeGet() + tcb->keepAlive;
		tcb->keepProbes = 0;
		TCPDEBUG((tcb->traceLevel + 1, TL_TCP, "tcpInput: Keepalive set for %lu", 
					(int)(tcb - & tcbs[0]),
					tcb->keepTime - OSTimeGet()));
		timeoutJiffy(
				&tcb->keepTimer, 
				tcb->keepTime, 
				keepTimeout, 
				tcb);
	}
	
	
	/* Do unsynchronized-state processing (p. 64-68) */
	switch(tcb->state){
	case CLOSED:
		if(tcpHdr->flags & TH_RST) {
			TCPDEBUG((tcb->traceLevel - 1, TL_TCP, "tcpInput[%d]: Dropping RESET on CLOSED",
					(int)(tcb - & tcbs[0])));
			STATS(tcpStats.resetIn.val++;)
			nFreeChain(inBuf);
		} else
			tcpReset(inBuf, ipHdr, tcpHdr, segLen);
		return;
	case LISTEN:
		if(tcpHdr->flags & TH_RST) {
			/*
			 * XXX - What would it mean if we got a reset on a listening
			 * connection?  After all, we shouldn't have sent anything!
			 */
			TCPDEBUG((tcb->traceLevel - 1, TL_TCP, "tcpInput[%d]: Dropping RESET on LISTEN",
					(int)(tcb - & tcbs[0])));
			STATS(tcpStats.resetIn.val++;)
			nFreeChain(inBuf);
			return;
		}
		if(tcpHdr->flags & TH_ACK){
			tcpReset(inBuf, ipHdr, tcpHdr, segLen);
			return;
		}
		if(tcpHdr->flags & TH_SYN){
			/* 
			 * Security check (RFC 793 pg 65) skipped here.
			 *
			 * Check incoming precedence (RFC 793 pg 66) and if it's
			 * greater than ours, upgrade ours.  In fact we actually
			 * adopt it's entire TOS.
			 */
			if(IPTOS_PREC(ipHdr->ip_tos) > IPTOS_PREC(tcb->ipTOS)) {
				TCPDEBUG((tcb->traceLevel - 1, TL_TCP, 
					"tcpInput[%d]: Changing TOS from %d to %d",
					(int)(tcb - & tcbs[0]), tcb->ipTOS, ipHdr->ip_tos));
				tcb->ipTOS = ipHdr->ip_tos;
			}
	
			STATS(tcpStats.conin.val++;)
			procSyn(tcb, tcpHdr);
			sendSyn(tcb);
			setState(tcb, SYN_RECEIVED);		
			/* If the segment contains no data then we're done. */
			if(segLen == 0 && !(tcpHdr->flags & TH_FIN)) {
				nFreeChain(inBuf);
				tcpOutput(tcb);
				return;
			}
		} else {
			TCPDEBUG((tcb->traceLevel - 1, TL_TCP, "tcpInput[%d]: Dropping non-SYN in LISTEN",
				(int)(tcb - & tcbs[0])));
			nFreeChain(inBuf);
			return;
		}
		/* At this point the segment contains data - continue processing. */
		break;
	case SYN_SENT:
		if(tcpHdr->flags & TH_ACK){
			if(!seqWithin(tcpHdr->ack, tcb->iss + 1, tcb->snd.nxt)) {
				tcpReset(inBuf, ipHdr, tcpHdr, segLen);
				return;
			}
		}
		if(tcpHdr->flags & TH_RST){	/* p 67 */
			if(tcpHdr->flags & TH_ACK){
				/*
				 * The ack must be acceptable since we just checked it.
				 * This is how the remote side refuses connect requests.
				 */
				closeSelf(tcb, TCPERR_RESET);
			}
			TCPDEBUG((tcb->traceLevel, TL_TCP, "tcpInput[%d]: Dropping RESET on SYN-SENT",
				(int)(tcb - & tcbs[0])));
			STATS(tcpStats.resetIn.val++;)
			nFreeChain(inBuf);
			return;
		}
		
		/* (Security check skipped here) */
		
		/* Check incoming precedence; it must match if there's an ACK */
		if(tcpHdr->flags & TH_ACK) {
			if(IPTOS_PREC(ipHdr->ip_tos) != IPTOS_PREC(tcb->ipTOS)) {
				TCPDEBUG((LOG_WARNING, TL_TCP, "tcpInput[%d]: in TOS PREC %u != our PREC %u",
						(int)(tcb - &tcbs[0]),
						IPTOS_PREC(ipHdr->ip_tos), 
						IPTOS_PREC(tcb->ipTOS)));
				tcpReset(inBuf, ipHdr, tcpHdr, segLen);
				return;
			}
		} else {
			if(IPTOS_PREC(ipHdr->ip_tos) > IPTOS_PREC(tcb->ipTOS)) {
				TCPDEBUG((tcb->traceLevel - 1, TL_TCP, 
					"tcpInput[%d]: Changing TOS from %d to %d",
					(int)(tcb - & tcbs[0]), tcb->ipTOS, ipHdr->ip_tos));
				tcb->ipTOS = ipHdr->ip_tos;
			}
		}
		
		if(tcpHdr->flags & TH_SYN){
			procSyn(tcb, tcpHdr);
			if(tcpHdr->flags & TH_ACK){
				/*
				 * Our SYN has been acked, otherwise the ACK
				 * wouldn't have been valid.
				 */
				tcbUpdate(tcb, tcpHdr);
				setState(tcb,ESTABLISHED);
			} else {
				setState(tcb,SYN_RECEIVED);
			}
			/* If no data then we're done. */
			if(segLen == 0 && !(tcpHdr->flags & TH_FIN)) {
				nFreeChain(inBuf);	
				tcpOutput(tcb);
				return;
			}
			
		/* Ignore segment if neither SYN or RST is set */
		} else {
			TCPDEBUG((tcb->traceLevel, TL_TCP, "tcpInput[%d]: Dropping non-SYN in SYN-SENT",
				(int)(tcb - & tcbs[0])));
			STATS(tcpStats.resetIn.val++;)
			nFreeChain(inBuf);	
			return;
		}
		
		/* At this point there is valid data in the segment so continue processing. */
		break;
	}
	
	/*
	 * We reach this point directly in any synchronized state. Note that
	 * if we fell through from LISTEN or SYN_SENT processing because of a
	 * data-bearing SYN, then window trimming and sequence testing "cannot
	 * fail".
	 */

	/*
	 * Trim segment to fit receive window.  If none of the segment is 
	 * acceptable, then if the segment isn't a reset, resend the last
	 * sent ACK. 
	 */
	if ((segLen = trimSeg(tcb, tcpHdr, inBuf, ipHeadLen + tcpHeadLen, segLen)) < 0) {
		if(!(tcpHdr->flags & TH_RST)){
			tcb->flags |= FORCE;
			tcpOutput(tcb);
		}
		TCPDEBUG((tcb->traceLevel - 1, TL_TCP, "tcpInput[%d]: Dropping unacceptable segment in %s", 
					(int)(tcb - & tcbs[0]),
					tcbStates[tcb->state]));
		STATS(tcpStats.resetIn.val++;)
		nFreeChain(inBuf);
		return;
	}
	
	/*
	 * Check the segment's flags and if OK and the ACK field is set, process
	 * the acknowledgement field here.  RFC 793 specifies that this is to
	 * be done when the segment begins with the next expected octet
	 * (i.e. at the top of the loop below) but we do it here so that we
	 * clear what we can from the output queue BEFORE we drop this due
	 * to a shortage of buffers or queue it in the resequencing queue.
	 */
	switch(procInFlags(tcb, tcpHdr, ipHdr)) {
	case ACKCLOSE:
		closeSelf(tcb, 0);
		/*** Fall through... ***/
	case ACKDROP:
		nFreeChain(inBuf);
		return;
		
	case ACKRESET:
		tcpReset(inBuf, ipHdr, tcpHdr, segLen);
		return;
	}
	
	/*
	 * Before continuing, check that there are enough free buffers for normal
	 * operation.  If not, we'll drop something.  If this is the next
	 * data expected, drop chains from the resequencing queue until we've
	 * cleared sufficient space.  If we're still short of buffers, drop this
	 * segment.
	 */
	if (nBUFSFREE() < tcb->minFreeBufs) {
		if(tcpHdr->seq == tcb->rcv.nxt) {
			while(nQHEAD(tcb->reseq) && nBUFSFREE() < tcb->minFreeBufs) {
				NBuf *segBuf;
				
				nDEQUEUE(tcb->reseq, segBuf);
				TCPDEBUG((tcb->traceLevel - 1, TL_TCP, 
							"tcpInput[%d]: Clearing reseq queue",
							(int)(tcb - & tcbs[0])));
				nFreeChain(segBuf);
			}
		}
		if (nBUFSFREE() < tcb->minFreeBufs) {
			TCPDEBUG((tcb->traceLevel - 1, TL_TCP, 
						"tcpInput[%d]: Drop due to insufficient free bufs",
						(int)(tcb - & tcbs[0])));
			nFreeChain(inBuf);
			inBuf = NULL;
		}
	
	/*
	 * If this segment isn't the next one expected and there's data
	 * or flags associated with it, put it on the resequencing
	 * queue, resend the current ACK, and return.
	 * NOTE: This may queue duplicate or overlapping segments.
	 */
	} else if(tcpHdr->seq != tcb->rcv.nxt
			&& (segLen > 0 || (tcpHdr->flags & TH_FIN))) {
		TCPDEBUG((tcb->traceLevel, TL_TCP, "tcpInput[%d]: Queued %u", 
					(int)(tcb - & tcbs[0]),
					segLen));
		nEnqSort(tcb->reseq, inBuf, tcpHdr->seq);
		inBuf = NULL;
		tcb->flags |= FORCE;
		tcpOutput(tcb);
	}

	/*
	 * This loop first processes the current segment, and then
	 * repeats while it can process segments from the resequencing queue.
	 */
	while (inBuf) {
		/*
		 * We reach this point with an acceptable segment; all data and flags
		 * are in the window, and the starting sequence number equals rcv.nxt
		 * (p. 70)
		 */	
		 
		/* (URGent bit processing skipped here) */

		/* Process the segment text, if any, beginning at rcv.nxt (p. 74) */
		if(segLen != 0){
			NBuf *segBuf = nSplit(inBuf, ipHeadLen + tcpHeadLen);
			
			switch(tcb->state){
			case SYN_RECEIVED:
			case ESTABLISHED:
			case FINWAIT1:
			case FINWAIT2:
				/* 
				 * Place the segment data on receive queue.  Keep the headers
				 * in a separate segment until we finish processing them below.
				 */
				nENQUEUE(&tcb->rcvq, segBuf);
				OS_ENTER_CRITICAL();
				tcb->rcvcnt += segLen;
				tcb->rcv.nxt += segLen;
				/* 
				 * Since we queue buffer chains and not characters, the receive
				 * window is adjusted by multiples of buffer lengths.
				 *
				 * XXX Here we assume that normally each buffer chain is of
				 * length 1.  If this is not the case, it may be better to
				 * adjust the buffer size rather than complicate this.  Only
				 * if you want to support greatly varying segment sizes would
				 * it be worth tracking the number of buffers in each chain.
				 */
				if ((tcb->rcv.wnd -= NBUFSZ) < 0)
					tcb->rcv.wnd = 0;
				tcb->flags |= FORCE;
				OS_EXIT_CRITICAL();
				break;
			default:
				/* Ignore segment text */
				nFreeChain(segBuf);
				TCPDEBUG((LOG_WARNING, TL_TCP, "tcpInput[%d]: State %d - dropped", 
							(int)(tcb - & tcbs[0]),
							tcb->state));
				break;
			}
		}
		
		/*
		 * Signal pending reads that data has arrived.
		 *
		 * This is done before sending an acknowledgement in case the 
		 * application is running at a higher priority and wants to piggyback
		 * some reply data.
		 *
		 * It's also done before processing FIN so that the CLOSED
		 * state will occur after the user has had a chance to read
		 * the last of the incoming data with a priority higher than
		 * we're running.
		 */
		if(tcb->rcvcnt != 0)
			OSSemPost(tcb->readSem);
		
		/* process FIN bit (p 75) */
		if(tcpHdr->flags & TH_FIN){
			tcb->flags |= FORCE;	/* Always respond with an ACK */

			switch(tcb->state){
			case SYN_RECEIVED:
			case ESTABLISHED:
				tcb->rcv.nxt++;
				setState(tcb, CLOSE_WAIT);
				break;
			case FINWAIT1:
				tcb->rcv.nxt++;
				if(tcb->sndcnt == 0) {
					/* Our FIN has been acked; bypass CLOSING state */
					setState(tcb, TIME_WAIT);
					tcb->retransTime = OSTimeGet() + MSL2 * TICKSPERSEC;
					TCPDEBUG((tcb->traceLevel, TL_TCP, "tcpInput[%d]: Timer %lu in %s", 
								(int)(tcb - & tcbs[0]),
								tcb->retransTime - OSTimeGet(), tcbStates[tcb->state]));
					timeoutJiffy(&tcb->resendTimer, tcb->retransTime, resendTimeout, tcb);
				} else {
					setState(tcb, CLOSING);
				}
				break;
			case FINWAIT2:
				tcb->rcv.nxt++;
				setState(tcb, TIME_WAIT);
				tcb->retransTime = OSTimeGet() + MSL2 * TICKSPERSEC;
				TCPDEBUG((tcb->traceLevel, TL_TCP, "tcpInput[%d]: Timer %lu in %s", 
							(int)(tcb - & tcbs[0]),
							tcb->retransTime - OSTimeGet(), tcbStates[tcb->state]));
				timeoutJiffy(&tcb->resendTimer, tcb->retransTime, resendTimeout, tcb);
				break;
			case CLOSE_WAIT:
			case CLOSING:
			case LAST_ACK:
				break;		/* Ignore */
			case TIME_WAIT:	/* p 76 */
				tcb->retransTime = OSTimeGet() + MSL2 * TICKSPERSEC;
				TCPDEBUG((tcb->traceLevel, TL_TCP, "tcpInput[%d]: Timer %lu in %s", 
							(int)(tcb - & tcbs[0]),
							tcb->retransTime - OSTimeGet(), tcbStates[tcb->state]));
				timeoutJiffy(&tcb->resendTimer, tcb->retransTime, resendTimeout, tcb);
				break;
			}
		}
		
		/* 
		 * We're done with this segment header.  If there was any data, it was
		 * dealt with earlier.
		 */
		nFreeChain(inBuf);
		inBuf = NULL;
		
		/* 
		 * Scan the resequencing queue, looking for a segment we can handle,
		 * and freeing all those that are now obsolete.
		 */
		while(segLen < 0 
				&& nQHEAD(tcb->reseq) 
				&& seqGE(tcb->rcv.nxt, nQHEADSORT(tcb->reseq))) {
			nDEQUEUE(tcb->reseq, inBuf);
			ipHdr = nBUFTOPTR(inBuf, IPHdr *);
			ipHeadLen = ipHdr->ip_hl * 4;
			tcpHdr = (TCPHdr *)((char *)ipHdr + ipHeadLen);
			tcpHeadLen = tcpHdr->tcpOff * 4;
			segLen = ipHdr->ip_len - ipHeadLen - tcpHeadLen;
			if ((segLen = trimSeg(tcb, tcpHdr, inBuf, ipHeadLen + tcpHeadLen, segLen)) < 0) {
				nFreeChain(inBuf);
				inBuf = NULL;
			}
		}
	}
	tcpOutput(tcb);	/* Send any necessary ack */
}

/* 
 * Get and set parameters for the given connection.
 * Return 0 on success, an error code on failure. 
 */
int  tcpIOCtl(u_int td, int cmd, void *arg)
{
	TCPCB *tcb = &tcbs[td];
	int st = 0;

	if (td >= MAXTCP || tcb->prev == tcb)
		st = TCPERR_PARAM;
	else {
		switch(cmd) {
		case TCPCTLG_UPSTATUS:		/* Get the TCP up status. */
			if (arg) 
				*(int *)arg = (tcb->state == ESTABLISHED);
			else
				st = TCPERR_PARAM;
			break;
		case TCPCTLG_RCVCNT:		/* Get the bytes in the receive queue. */
			if (arg)
				*(int *)arg = (int)tcb->rcvcnt;
			else
				st = TCPERR_PARAM;
			break;
		case TCPCTLG_KEEPALIVE:		/* Get the TCP keepalive period. */
			if (arg) 
				*(int *)arg = (int)(tcb->keepAlive / TICKSPERSEC);
			else
				st = TCPERR_PARAM;
			break;
		case TCPCTLS_KEEPALIVE:		/* Set the TCP keepalive period. */
			if (arg) 
				tcb->keepAlive = (u_long)(*(int *)arg) * TICKSPERSEC;
			else
				st = TCPERR_PARAM;
			break;
		case TCPCTLG_TRACELEVEL:	/* Get the TCP trace level. */
			if (arg) 
				*(int *)arg = tcb->traceLevel;
			else
				st = TCPERR_PARAM;
			break;
		case TCPCTLS_TRACELEVEL:	/* Set the TCP trace level. */
			if (arg) 
				tcb->traceLevel = *(int *)arg;
			else
				st = TCPERR_PARAM;
			break;
		default:
			st = TCPERR_PARAM;
			break;
		}
	}
	
	return st;
}


/**********************************/
/*** LOCAL FUNCTION DEFINITIONS ***/
/**********************************/
#if ECHO_SUPPORT > 0
/*
 * tcpEcho - The TCP echo server.  This will handle a single TCP echo
 * connection at a time.
 */
#pragma argsused
static void tcpEcho(void *arg)
{
	#define TCPECHOBUFSZ 50
	struct sockaddr_in localAddr, peerAddr;
	int td, ntd, inCnt, outCnt;
	char tBuf[TCPECHOBUFSZ];
	
	localAddr.ipAddr = localHost;
	localAddr.sin_port = TCPPORT_ECHO;
	
	if ((td = tcpOpen()) < 0) {
		ECHODEBUG((LOG_ERR, TL_ECHO, "tcpEcho: Unable to open a TCB (%d)", td));
	} else if ((inCnt = 10) != 0 
			&& (outCnt = tcpIOCtl(td, TCPCTLS_KEEPALIVE, &inCnt)) < 0) {
		ECHODEBUG((LOG_ERR, TL_ECHO, "tcpEcho: Error %d setting keep alive", outCnt));
	} else for (;;) {
		if ((inCnt = tcpBind(td, &localAddr)) < 0) {
			ECHODEBUG((LOG_ERR, TL_ECHO, "tcpEcho: Error %d on bind", inCnt));
			break;
		} else if ((ntd = tcpAccept(td, &peerAddr)) < 0) {
			ECHODEBUG((LOG_ERR, TL_ECHO, "tcpEcho: Error %d on accept", ntd));
			break;
		} else {
			ECHODEBUG((LOG_INFO, TL_ECHO, "tcpEcho: connect %s:%u",
						ip_ntoa(htonl(peerAddr.sin_addr.s_addr)),
						peerAddr.sin_port));
			while ((inCnt = tcpRead(ntd, tBuf, TCPECHOBUFSZ)) >= 0) {
				if ((outCnt = tcpWrite(ntd, tBuf, inCnt)) < inCnt) {
					if (outCnt != TCPERR_EOF) {
						ECHODEBUG((LOG_ERR, TL_ECHO, "tcpEcho: TCP write err %d", outCnt));
					}
					break;
				}
			}
			if (inCnt != TCPERR_EOF) {
				ECHODEBUG((LOG_ERR, TL_ECHO, "tcpEcho: TCP read err %d", inCnt));
			}
		}
		if (ntd >= 0) {
			ECHODEBUG((LOG_INFO, TL_ECHO, "tcpEcho: disconnect %d %s:%u", ntd,
						ip_ntoa(htonl(peerAddr.sin_addr.s_addr)),
						peerAddr.sin_port));
			if ((inCnt = tcpDisconnect(ntd)) < 0) {
				ECHODEBUG((LOG_ERR, TL_ECHO, "tcpEcho: Disconnect err %d", inCnt));
				break;
				
			} else if ((inCnt = tcpWait(ntd)) < 0) {
				ECHODEBUG((LOG_ERR, TL_ECHO, "tcpEcho: Close wait err %d", inCnt));
				break;
			}
		}
	}
	if (td >= 0 && td != ntd) {
		ECHODEBUG((LOG_INFO, TL_ECHO, "tcpEcho: disconnect %d %s:%u", td,
					ip_ntoa(htonl(peerAddr.sin_addr.s_addr)),
					peerAddr.sin_port));
		if ((inCnt = tcpDisconnect(td)) < 0) {
			ECHODEBUG((LOG_ERR, TL_ECHO, "tcpEcho: Disconnect err %d", inCnt));
		}
	}
	OSTaskDel(OS_PRIO_SELF);
}
#endif


/*
 * resendTimeout - The function invoked when the resend timer expires.
 */
static void resendTimeout(void *arg)
{
	register TCPCB *tcb = (TCPCB *)arg;

	if(tcb == NULL) {
		TCPDEBUG((LOG_ERR, TL_TCP, "resendTimeout: Null arg"));
		return;
	} else if (tcb->state == CLOSED) {
		TCPDEBUG((LOG_ERR, TL_TCP, "resendTimeout: Connection closed"));
		return;
	}

	/* Make sure the timer has stopped (we might have been kicked) */
	timerClear(&tcb->resendTimer); 

	TCPDEBUG((tcb->traceLevel, TL_TCP, "resendTimeout[%d]: state=%s", 
				(int)(tcb - &tcbs[0]),
				tcbStates[tcb->state]));
				
	/* 
	 * Check if the timer was set (i.e. there is unacknowledged output 
	 * or we're in TIME_WAIT or in FINWAIT2).
	 */
	if (tcb->snd.una != tcb->snd.nxt 
			|| tcb->state == TIME_WAIT || (tcb->state == FINWAIT2)) {
		/* If the timer hasn't expired, reset it. */
		if (diffTime(tcb->retransTime) > 0) {
			TCPDEBUG((tcb->traceLevel, TL_TCP, 
						"resendTimeout[%d]: Timer reset for %lu in %s", 
						(int)(tcb - & tcbs[0]),
						tcb->retransTime - OSTimeGet(), tcbStates[tcb->state]));
			timeoutJiffy(&tcb->resendTimer, tcb->retransTime, resendTimeout, tcb);
		
		/* Otherwise resend the last unacknowledged segment. */
		} else {
			/* CRITICAL - Prevent tcpInput from updating retransCnt at same time. */
			OS_ENTER_CRITICAL();
			/*
			 * If it's the 2MSL timer that has expired or if we've timed out in
			 * FINWAIT2 close the connection without error. 
			 */
			if (tcb->state == TIME_WAIT 
					|| (tcb->state == FINWAIT2 && tcb->freeOnClose)) {
				OS_EXIT_CRITICAL();
				closeSelf(tcb, 0);
				
			/* Check if we've timed out on retransmissions. */
			} else if (tcb->retransCnt++ >= MAXRETRANS) {
				OS_EXIT_CRITICAL();
				closeSelf(tcb, TCPERR_TIMEOUT);
				
			/* Normal retransmission timeout - reset pointers and invoke tcpOutput(). */
			} else {
				OS_EXIT_CRITICAL();

				/* 
				 * Wait for tcpOutput() to clear critical section before setting
				 * up for resend.
				 */
				OSSemPend(tcb->mutex, 0);
				tcb->flags |= RETRAN;	/* Indicate > 1  transmission */
				tcb->backoff++;
				tcb->snd.ptr = tcb->snd.una;
				/* Reduce slowstart threshold to half current window */
				tcb->ssthresh = tcb->cwind / 2;
				tcb->ssthresh = MAX(tcb->ssthresh, tcb->mss);
				/* Shrink congestion window to 1 packet */
				tcb->cwind = tcb->mss;
				OSSemPost(tcb->mutex);
				
				tcpOutput(tcb);
			}
		}
	}
}
		
	
/*
 * keepTimeout - The function invoked when the keep alive timer expires.
 */
static void keepTimeout(void *arg)
{
	register TCPCB *tcb = (TCPCB *)arg;

	/* Check if we're doing keep alives. */
	if (tcb->keepAlive 
			&& (tcb->state == ESTABLISHED
				|| tcb->state == CLOSE_WAIT)) {
		/* 
		 * If we've received something less recently than the keep alive time,
		 * then reset the timer.
		 */
		if ((long)(OSTimeGet() - tcb->keepTime) < 0) {
			TCPDEBUG((tcb->traceLevel, TL_TCP, 
						"keepTimeout[%d]: Keepalive reset for %lu in %s", 
						(int)(tcb - & tcbs[0]),
						tcb->keepTime - OSTimeGet(), 
						tcbStates[tcb->state]));
			timeoutJiffy(
					&tcb->keepTimer, 
					tcb->keepTime, 
					keepTimeout, 
					tcb);
					
		/*
		 * If we've exceeded our maximum keep alive timeouts, close the
		 * connection.
		 */
		} else if (tcb->keepProbes++ >= MAXKEEPTIMES) {
			TCPDEBUG((LOG_WARNING, TL_TCP, 
						"keepTimeout[%d]: Keepalive expired - closing",
						(int)(tcb - & tcbs[0])));
			closeSelf(tcb, TCPERR_TIMEOUT);
			
		/*
		 * Reset the timer and send a keep alive probe.
		 */
		} else {
			tcb->keepTime = OSTimeGet() + tcb->keepAlive;
			TCPDEBUG((tcb->traceLevel, TL_TCP, 
						"keepTimeout[%d]: Keepalive set for %lu in %s", 
						(int)(tcb - & tcbs[0]),
						tcb->keepTime - OSTimeGet(), 
						tcbStates[tcb->state]));
			timeoutJiffy(
					&tcb->keepTimer, 
					tcb->keepTime, 
					keepTimeout, 
					tcb);
			
			OS_ENTER_CRITICAL();
			tcb->flags |= FORCE | KEEPALIVE;
			OS_EXIT_CRITICAL();
			
			tcpOutput(tcb);
		}
	}
}


static void setState(TCPCB *tcb, TCPState newState)
{
	register TCPState oldState;

	OS_ENTER_CRITICAL();
	if ((oldState = tcb->state) != newState) {
		tcb->state = newState;
		OS_EXIT_CRITICAL();
		
		TCPDEBUG((tcb->traceLevel, TL_TCP, "setState[%d]: %s from %s",
					(int)(tcb - &tcbs[0]),
					tcbStates[newState], tcbStates[oldState]));
					
		switch(newState){
		case FINWAIT2:
			/* 
			 * Limit the time that we'll wait for the other end to close.
			 * XXX To support a half close, you'll need to test for something
			 * here.
			 */
			tcb->retransTime = OSTimeGet() + MAXFINWAIT2 * TICKSPERSEC;
			TCPDEBUG((tcb->traceLevel + 1, TL_TCP, "setState[%d]: Timer %lu in %s", 
						(int)(tcb - & tcbs[0]),
						tcb->retransTime - OSTimeGet(), tcbStates[tcb->state]));
			timeoutJiffy(&tcb->resendTimer, tcb->retransTime, resendTimeout, tcb);
			/* FALL THROUGH... */
		case CLOSED:
		case ESTABLISHED:
		case LISTEN:
		case SYN_SENT:
		case SYN_RECEIVED:
		case FINWAIT1:
		case CLOSE_WAIT:
		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
			/* 
			 * Inform user processes that the state has changed.  This leaves it
			 * up to the individual processes to decide if the new state is
			 * significant and if not, then to pend again.  Unfortunately
			 * uC/OS cannot tell us how many processes are waiting on any of
			 * these so we assume that there is at most one and if there is
			 * not one, it won't hurt doing the extra posts.
			 */
			OSSemPost(tcb->connectSem);
			OSSemPost(tcb->readSem);
			OSSemPost(tcb->writeSem);

			break;
			
		default:
			trace(LOG_ERR, "setState: Invalid new state %d old %d",
					newState, oldState);
			tcb->state = oldState;
			break;
		}
		
		/* If we're closed then free or unlink the control block. */
		if (newState == CLOSED) {
			if (tcb->freeOnClose)
				tcbFree(tcb);
			else
				tcbUnlink(tcb);
		}
	} else {
		OS_EXIT_CRITICAL();
	}
	
}

/*
 * Process an incoming acknowledgement and window indication.
 * From RFC page 70.
 * Return zero if successful, ACKDROP if the segment should
 * be dropped, ACKRESET if the segment should be rejected,
 * and ACKCLOSE if the connection is closed.
 */
static int procInFlags(TCPCB *tcb, TCPHdr *tcpHdr, IPHdr *ipHdr)
{
	int st = ACKOK;
	
	if(tcpHdr->flags & RST) {
		if(tcb->state == SYN_RECEIVED
			 && !(tcb->flags & (CLONE | ACTIVE))) {
			/* 
			 * Go back to listen state only if this was
			 * not a cloned or active server TCB since
			 * the tcpAccept() call hasn't returned yet.
			 */
			tcbUnlink(tcb);
			tcb->conn.remoteIPAddr = 0;
			tcb->conn.remotePort = 0;
			tcbLink(tcb);
			setState(tcb, LISTEN);
		} else {
			closeSelf(tcb, TCPERR_RESET);
		}
		TCPDEBUG((tcb->traceLevel, TL_TCP, "procInFlags[%d]: Dropping RESET in %s", 
					(int)(tcb - & tcbs[0]),
					tcbStates[tcb->state]));
		STATS(tcpStats.resetIn.val++;)
		st = ACKDROP;
	
	/* (Security check skipped here) p. 71 */
	
	/* Check for precedence mismatch. */
	} else if((ipHdr->ip_tos & IPTOS_PREC_MASK) != (tcb->ipTOS & IPTOS_PREC_MASK)) {
		TCPDEBUG((LOG_WARNING, TL_TCP, "procInFlags[%d]: Rejecting prec mismatch in %s", 
					(int)(tcb - & tcbs[0]),
					tcbStates[tcb->state]));
		st = ACKRESET;
		
	/* Check for erroneous extra SYN */
	} else if (tcpHdr->flags & SYN) {
		TCPDEBUG((tcb->traceLevel, TL_TCP, "procInFlags[%d]: Rejecting SYN in %s", 
					(int)(tcb - & tcbs[0]),
					tcbStates[tcb->state]));
		st = ACKRESET;

	/* Check ack field p. 72 */
	/* All segments after synchronization must have ACK */
	} else if(!(tcpHdr->flags & TH_ACK)) {
		TCPDEBUG((LOG_WARNING, TL_TCP, "procInFlags[%d]: Dropping non-ACK in %s",
					(int)(tcb - & tcbs[0]),
					tcbStates[tcb->state]));
		st = ACKDROP;
	
	/* Process ACK */
	} else switch(tcb->state) {
	case SYN_RECEIVED:
		if(seqWithin(tcpHdr->ack, tcb->snd.una + 1, tcb->snd.nxt)) {
			tcbUpdate(tcb, tcpHdr);
			setState(tcb, ESTABLISHED);
		} else {
			st = ACKRESET;
		}
		break;
	case ESTABLISHED:
	case CLOSE_WAIT:
		tcbUpdate(tcb, tcpHdr);
		break;
	case FINWAIT1:	/* p. 73 */
		tcbUpdate(tcb, tcpHdr);
		if(tcb->sndcnt == 0) {
			/* Our FIN is acknowledged */
			setState(tcb, FINWAIT2);
		}
		break;
	case FINWAIT2:
		tcbUpdate(tcb, tcpHdr);
		/* 
		 * We're still getting something on this connection so reset the
		 * FINWAIT2 timeout.
		 */
		tcb->retransTime = OSTimeGet() + MAXFINWAIT2 * TICKSPERSEC;
		TCPDEBUG((tcb->traceLevel, TL_TCP, "procInFlags[%d]: Timer %lu in %s", 
					(int)(tcb - & tcbs[0]),
					tcb->retransTime - OSTimeGet(), tcbStates[tcb->state]));
		timeoutJiffy(&tcb->resendTimer, tcb->retransTime, resendTimeout, tcb);
		break;
	case CLOSING:
		tcbUpdate(tcb, tcpHdr);
		if(tcb->sndcnt == 0) {
			/* Our FIN is acknowledged */
			setState(tcb, TIME_WAIT);
			tcb->retransTime = OSTimeGet() + MSL2 * TICKSPERSEC;
			TCPDEBUG((tcb->traceLevel, TL_TCP, "procInFlags[%d]: Timer %lu in %s", 
						(int)(tcb - & tcbs[0]),
						tcb->retransTime - OSTimeGet(), tcbStates[tcb->state]));
			timeoutJiffy(&tcb->resendTimer, tcb->retransTime, resendTimeout, tcb);
		}
		break;
	case LAST_ACK:
		tcbUpdate(tcb, tcpHdr);
		if(tcb->sndcnt == 0) {
			/* Our FIN is acknowledged, close connection */
			st = ACKCLOSE;
		}
		break;
	case TIME_WAIT:
/* I think this is wrong, and can cause permanent ACK-ACK loops.  dmf.
		tcb->flags |= FORCE;
		tcb->retransTime = OSTimeGet() + MSL2 * TICKSPERSEC;
		timeoutJiffy(&tcb->resendTimer, tcb->retransTime, resendTimeout, tcb);
*/
		break;
	}
	
	return st;
}


/*
 * tcbInit - Initialize TCPCB parameters to default values.
 * This is used when a new connection is being established.
 */
static void tcbInit(register TCPCB *tcb)
{
		/* Initialize TCP parameters. */
		tcb->cwind = TCP_DEFMSS;
		tcb->ssthresh = TCP_ISSTHRESH;
		tcb->srtt = TCP_DEFRTT;
	
		/* Initialize header cache. */
		tcb->ipVersion = IPVERSION;
		tcb->ipHdrLen = sizeof(IPHdr) / 4;
		tcb->ipTOS = 0;
		tcb->ipTTL = 0;	/* TTL set to zero here for TCP checksum calculation. */
		tcb->ipProto = IPPROTO_TCP;
}

		
/*
 * Process an incoming acknowledgement and window indication.
 * From page 72.
 */
static void tcbUpdate(register TCPCB *tcb, register TCPHdr *tcpHdr)
{
	u_int16_t acked;
	u_int16_t expand;

	acked = 0;
	
	OSSemPend(tcb->mutex, 0);
	if(seqGT(tcpHdr->ack, tcb->snd.nxt)) {
		tcb->flags |= FORCE;	/* Acks something not yet sent */
		OSSemPost(tcb->mutex);
		return;
	}
	/*
	 * Decide if we need to do a window update.
	 * This is always checked whenever a legal ACK is received,
	 * even if it doesn't actually acknowledge anything,
	 * because it might be a spontaneous window reopening.
	 */
	if(seqGT(tcpHdr->seq, tcb->snd.wl1) 
			|| ((tcpHdr->seq == tcb->snd.wl1) 
				&& seqGE(tcpHdr->ack, tcb->snd.wl2))) {
		/*
		 * If the window had been closed, crank back the
		 * send pointer so we'll immediately resume transmission.
		 * Otherwise we'd have to wait until the next probe.
		 */
		if(tcb->snd.wnd == 0 && tcpHdr->win != 0)
			tcb->snd.ptr = tcb->snd.una;
		tcb->snd.wnd = tcpHdr->win;
		tcb->snd.wl1 = tcpHdr->seq;
		tcb->snd.wl2 = tcpHdr->ack;
	}
	/* See if anything new is being acknowledged */
	if(!seqGT(tcpHdr->ack, tcb->snd.una)) {
		OSSemPost(tcb->mutex);
		return;	/* Nothing more to do */
	}

	/* We're here, so the ACK must have actually acked something */
	acked = (u_int16_t)(tcpHdr->ack - tcb->snd.una);

	/* Expand congestion window if not already at limit */
	if(tcb->cwind < tcb->snd.wnd) {
		if(tcb->cwind < tcb->ssthresh){
			/* Still doing slow start/CUTE, expand by amount acked */
			expand = MIN(acked, tcb->mss);
		} else {
			/* Steady-state test of extra path capacity */
			expand = (u_int16_t)(((long)tcb->mss * tcb->mss) / tcb->cwind);
		}
		/* Guard against arithmetic overflow */
		if(tcb->cwind + expand < tcb->cwind)
			expand = INT_MAX - tcb->cwind;

		/* Don't expand beyond the offered window */
		if(tcb->cwind + expand > tcb->snd.wnd)
			expand = tcb->snd.wnd - tcb->cwind;

		if(expand != 0){
#ifdef	notdef
			/* Kick up the mean deviation estimate to prevent
			 * unnecessary retransmission should we already be
			 * bandwidth limited
			 */
			tcb->mdev += ((long)tcb->srtt * expand) / tcb->cwind;
#endif
			tcb->cwind += expand;
		}
	}
	/* Round trip time estimation */
	if(tcb->rttStart && seqGE(tcpHdr->ack, tcb->rttseq)) {
		long rttElapsed;
		
		/* A timed sequence number has been acked */
		rttElapsed = -diffTime(tcb->rttStart);
		tcb->rttStart = 0;
		if(!(tcb->flags & RETRAN)){
		u_int32_t abserr;	/* abs(rtt - srtt) */

			/*
			 * This packet was sent only once and now
			 * it's been acked, so process the round trip time.
			 *
			 * If this ACKs our SYN, this is the first ACK
			 * we've received; base our entire SRTT estimate
			 * on it. Otherwise average it in with the prior
			 * history, also computing mean deviation.
			 */
			if(rttElapsed > tcb->srtt 
					&& (tcb->state == SYN_SENT || tcb->state == SYN_RECEIVED)) {
				tcb->srtt = rttElapsed;
			} else {
				abserr = (rttElapsed > tcb->srtt) 
					? rttElapsed - tcb->srtt : tcb->srtt - rttElapsed;
				tcb->srtt = ((AGAIN-1)*tcb->srtt + rttElapsed) / AGAIN;
				tcb->mdev = ((DGAIN-1)*tcb->mdev + abserr) / DGAIN;
			}
			/* Reset the backoff level */
			tcb->backoff = 0;
		}
	}
	/* If we're waiting for an ack of our SYN, note it and adjust count */
	if(!(tcb->flags & SYNACK)){
		tcb->flags |= SYNACK;
		acked--;
		tcb->sndcnt--;
	}
	/*
	 * Remove acknowledged bytes from the send queue and update the
	 * unacknowledged pointer. If a FIN is being acked,
	 * pullup won't be able to remove it from the queue.
	 */
	nTrimQ(NULL, &tcb->sndq, acked);

	/* This will include the FIN if there is one */
	tcb->sndcnt -= acked;
	tcb->snd.una = tcpHdr->ack;

	/*
	 * Stop retransmission timer, but restart it if there is still
	 * unacknowledged data.
	 */	
	timerClear(&tcb->resendTimer);
	if(tcb->snd.una != tcb->snd.nxt) {
		tcb->retransTime = OSTimeGet()
			+ backOff(tcb->backoff) 
				* (2 * tcb->mdev + tcb->srtt + MSPERTICK) 
				/ MSPERTICK;
		TCPDEBUG((tcb->traceLevel + 2, TL_TCP, "tcbUpdate[%d]: Timer %lu in %s", 
					(int)(tcb - & tcbs[0]),
					tcb->retransTime - OSTimeGet(), tcbStates[tcb->state]));
		timeoutJiffy(&tcb->resendTimer, tcb->retransTime, resendTimeout, tcb);
	}

	/*
	 * If retransmissions have been occurring, make sure the
	 * send pointer doesn't repeat ancient history
	 */
	if(seqLT(tcb->snd.ptr, tcb->snd.una))
		tcb->snd.ptr = tcb->snd.una;

	/*
	 * Clear the retransmission flag since the oldest
	 * unacknowledged segment (the only one that is ever retransmitted)
	 * has now been acked.
	 */
	tcb->flags &= ~RETRAN;
	
	OSSemPost(tcb->mutex);

	TCPDEBUG((tcb->traceLevel + 2, TL_TCP,
				"tcbUpdate[%d]: snd(una=%lu,nxt=%lu,ptr=%lu,wnd=%u)",
				(int)(tcb - &tcbs[0]),
				tcb->snd.una,
				tcb->snd.nxt,
				tcb->snd.ptr,
				tcb->snd.wnd));
	TCPDEBUG((tcb->traceLevel + 2, TL_TCP, "tcbUpdate[%d]: snd(wl1=%lu,wl2=%lu)",		
				(int)(tcb - &tcbs[0]),
				tcb->snd.wl1,
				tcb->snd.wl2));
	TCPDEBUG((tcb->traceLevel + 2, TL_TCP,
				"tcbUpdate[%d]: iss=%lu cwin=%u sst=%u res=%lu backoff=%u",
				(int)(tcb - &tcbs[0]),
				tcb->iss,
				tcb->cwind,
				tcb->ssthresh,
				tcb->resent,
				tcb->backoff));
	TCPDEBUG((tcb->traceLevel + 2, TL_TCP,
				"tcbUpdate[%d]: rcv(nxt=%lu,wnd=%u,up=%u) irs=%lu mss=%u",
				(int)(tcb - &tcbs[0]),
				tcb->rcv.nxt,
				tcb->rcv.wnd,
				tcb->rcv.up,
				tcb->irs,
				tcb->mss,
				tcb->rerecv));
				
	/*
	 * If outgoing data was acked, clear the retransmission count and
	 * notify the user so he can send more unless we've already sent a FIN.
	 */
	if(acked) {
		/* Prevent resendTimeout from updating retransCnt at the same time. */
		OS_ENTER_CRITICAL();
		tcb->retransCnt = 0;
		OS_EXIT_CRITICAL();
		
		switch(tcb->state){
	 	case ESTABLISHED:
		case CLOSE_WAIT:
			OSSemPost(tcb->writeSem);
		}
	}
}

/* Process an incoming SYN */
static void procSyn(register TCPCB *tcb, TCPHdr *tcpHdr)
{
	OSSemPend(tcb->mutex, 0);
	tcb->flags |= FORCE;	/* Always send a response */

	/*
	 * Note: It's not specified in RFC 793, but SND.WL1 and
	 * SND.WND are initialized here since it's possible for the
	 * window update routine in tcbUpdate() to fail depending on the
	 * IRS if they are left unitialized.
	 */
	tcb->rcv.nxt = tcpHdr->seq + 1;	/* p 68 */
	tcb->snd.wl1 = tcb->irs = tcpHdr->seq;
	tcb->snd.wnd = tcpHdr->win;
	/* XXX Should check for TCP options - especially MSS. */
	OSSemPost(tcb->mutex);
}

/* Generate an initial sequence number and put a SYN on the send queue */
void sendSyn(register TCPCB *tcb)
{
	OSSemPend(tcb->mutex, 0);
	tcb->snd.ptr 
		= tcb->snd.nxt 
		= tcb->rttseq
		= tcb->snd.wl2 
		= tcb->snd.una 
		= tcb->iss
			= newISS();
	tcb->sndcnt++;
	tcb->flags |= FORCE;
	OSSemPost(tcb->mutex);
}

/* 
 * Return an initial sequence number.  According to RFC 793 pg 27,
 * "The generator is bound to a 32 bit clock whose low order bit is
 * incremented roughly every 4 microseconds.  Thus, the ISN cycles
 * approximately every 4.55 hours."  Our generator uses an initial
 * random value added to 250 times our millisecond clock.
 * Return: New ISN.
 */
u_int32_t newISS(void)
{
	return newISNOffset + mtime() * 250;
}

/* closeSelf - Close our connection. */
static void closeSelf(register TCPCB *tcb, int reason)
{
	tcb->closeReason = reason;
	setState(tcb, CLOSED);
}

/* 
 * tcbFree - Discard all the queues and free the TCB (it's assumed to be 
 * closed).
 */
static void tcbFree(TCPCB *tcb)
{
	NBuf *n0;

    /* Check that the TCB is not already on the free list. */    
    if (tcb->prev != tcb) {
		tcbUnlink(tcb);
		timerClear(&tcb->resendTimer);
		timerClear(&tcb->keepTimer);
		tcb->rttStart = 0;
		while (nQHEAD(tcb->reseq)) {
			nDEQUEUE(tcb->reseq, n0);
			nFreeChain(n0);
		}
		while (nQHEAD(&tcb->rcvq)) {
			nDEQUEUE(&tcb->rcvq, n0);
			nFreeChain(n0);
		}
		tcb->rcvcnt = 0;
		while (nQHEAD(&tcb->sndq)) {
			nDEQUEUE(&tcb->sndq, n0);
			nFreeChain(n0);
		}
		tcb->sndcnt = 0;
		if (tcb->rcvBuf) {
			nFreeChain(tcb->rcvBuf);
			tcb->rcvBuf = NULL;
		}
		/* Reset the backoff level */
		tcb->backoff = 0;
		tcb->snd.nxt 
			= tcb->rttseq
			= tcb->snd.wl2 
			= tcb->snd.una 
			= tcb->iss
			= tcb->snd.ptr;
		tcb->flags = 0;
		
		OS_ENTER_CRITICAL();
		tcb->next = topTcpCB;
		topTcpCB = tcb->prev = tcb;	/* Prev -> self => tcb on free list. */
		STATS(tcpStats.curFree.val++;)
		OS_EXIT_CRITICAL();
	}
}	

/* 
 * tcpOutput - Send a prepared TCP segment.
 * One gets sent from the output queue only if there is data to be sent or if
 * "force" is non zero.
 */
static void tcpOutput(TCPCB *tcb)
{
	IPHdr *ipHdr;			/* Ptr to IP hdr in output buffer. */
	TCPHdr *tcpHdr;			/* Ptr to TCP hdr in output buffer. */
	NBuf  *sBuf;			/* Segment buffer. */
	u_int16_t hsize;			/* Size of header */
	u_int16_t ssize;			/* Size of current segment being sent,
							 * including SYN and FIN flags */
	u_int16_t dsize;			/* Size of segment less SYN and FIN */
	u_int16_t sent;				/* Sequence count (incl SYN/FIN) already in the pipe */

	if (tcb == NULL || tcb->state == LISTEN || tcb->state == CLOSED)
		;
	else {
		OSSemPend(tcb->mutex, 0);
		for(;;) {
			
			sent = (u_int16_t)(tcb->snd.ptr - tcb->snd.una);
			if (sent < 0) {
				TCPDEBUG((LOG_ERR, TL_TCP, "tcpOutput[%d]: sent=%d una=%lu ptr=%lu",
							(int)(tcb - & tcbs[0]),
							sent, tcb->snd.una, tcb->snd.ptr));
			}

			/* Don't send anything else until our SYN has been acked */
			if (sent != 0 && !(tcb->flags & SYNACK))
				break;
	
			/* Compute usable window that we could send. */
			if (tcb->snd.wnd == 0) {
				/* Allow only one closed-window probe at a time */
				if (sent != 0)
					ssize = 0;
				/* Force a closed-window probe */
				else
					ssize = 1;
			} else {
				/* 
				 * Usable window = offered window (limited by the congestion 
				 * window) less the unacked bytes in transit.
				 */
				ssize = MIN(tcb->snd.wnd, tcb->cwind) - sent;
			}
			/*
			 * Compute size of segment to send. This is either the usable
			 * window, the mss, or the amount we have on hand, whichever is less.
			 * (I don't like optimistic windows)
			 */
			ssize = MIN(tcb->sndcnt - sent, ssize);
			ssize = MIN(ssize, tcb->mss);
	
			/*
			 * Allow only a single outstanding segment unless we are
			 * sending enough data to form at least one minimum-sized segment
			 * (i.e. a variation on John Nagle's "single outstanding segment" 
			 * rule which is for a maximum-size segment) or
			 * if we have used up our quota of segments on the output queue or
			 * if this is the very last packet.
			 */
			if (sent != 0 && ssize < TCP_MINSEG
					&& tcb->sndq.qLen < TCP_MAXQUEUE 
					&& !(tcb->state == FINWAIT1 && ssize == tcb->sndcnt - sent))
				ssize = 0;
				
			/*
			 * Abort if we're sending neither data nor an ACK.
			 */
			if(ssize == 0 && !(tcb->flags & FORCE))
				break;
				
			/*
			 * We've handled the FORCE flag (if any) so clear it.
			 */	
			tcb->flags &= ~FORCE;
	
			/*
			 * Set the SYN and ACK flags according to the state we're in. It is
			 * assumed that if this segment is associated with a state transition,
			 * then the state change will already have been made. This allows
			 * this routine to be called from a retransmission timeout with
			 * force=1.
			 * If SYN is being sent, adjust the dsize counter so we'll
			 * try to get the right amount of data off the send queue.
			 */
			tcb->tcpFlags = TH_ACK; 		/* Every state except SYN_SENT */
			dsize = ssize;
			hsize = sizeof(TCPHdr) + sizeof(IPHdr);	/* Except when SYN being sent */
			tcb->optionsPtr = tcb->tcpOptions;	/* Reset the TCP options. */
			switch(tcb->state) {
			case SYN_SENT:
				/* Waiting for a SYN reply so we don't ACK yet. */
				tcb->tcpFlags = 0;
				/* FALL THROUGH! */
			case SYN_RECEIVED:
				/*
				 * If we're (re)sending the first data of the connection, then
				 * it's a SYN reply with an MSS option.
				 */
				if (tcb->snd.ptr == tcb->iss){
					tcb->tcpFlags |= SYN;
					dsize--;
					hsize += TCPOLEN_MAXSEG;
					*tcb->optionsPtr++ = TCPOPT_MAXSEG;
					*tcb->optionsPtr++ = TCPOLEN_MAXSEG;
					put16(tcb->optionsPtr, tcb->mss);
				}
				break;
			}
			
			/* 
			 * Set the sequence, ack, window, and urgent values for the segment
			 * to send.  If we're sending a keep alive then we send a segment
			 * with the sequence set to that of the last acknowledged octet. 
			 * Otherwise, the sequence is that of the next octet to send. 
			 * Whatever the case, we clear the keep alive because the link is
			 * active.
			 */
			if (dsize == 0 && (tcb->flags & KEEPALIVE))
				tcb->tcpSeq = htonl(tcb->snd.una - 1);
			else
				tcb->tcpSeq = htonl(tcb->snd.ptr);
			tcb->tcpAck = htonl(tcb->rcv.nxt);
			tcb->tcpWin = htons(tcb->rcv.wnd);
			tcb->tcpUrgent = 0;
			
			/*
			 * Start a new buffer chain, reserve space for the link, IP,
			 * and TCP headers.
			 */
			nGET(sBuf);
			if (!sBuf) {
				TCPDEBUG((LOG_ERR, TL_TCP, "tcpOutput[%d]: No free buffers!",
							(int)(tcb - & tcbs[0])));
				break;
			}
			nADVANCE(sBuf, MAXIFHDR + hsize);

			/*
			 * Now try to load the data for the outgoing segment from the send queue.
			 * Since SYN and FIN occupy sequence space and are reflected
			 * in sndcnt but don't actually sit in the send queue,
			 * append will return one less than dsize if a FIN needs to be sent.
			 */
			/* XXX Don't like this!  Append could have failed to allocate.  Prefer
			 * to have FIN coded in the tcb flags. */
			if (dsize > 0) {
				if (nAppendFromQ(sBuf, &tcb->sndq, sent, dsize) != dsize) {
					tcb->tcpFlags |= FIN;
					dsize--;
				}
				
			/* 
			 * If we're just sending a keep alive probe, append a dummy character
			 * to please those stacks that don't respond to empty segments.
			 */
			} else if (tcb->flags & KEEPALIVE) {
				char c = '?';
				
				nAPPENDCHAR(sBuf, c, dsize)
			}
			tcb->flags &= ~KEEPALIVE;
	
			/*
			 * If the entire send queue will now be in the pipe, set the
			 * push flag.
			 */
			OS_ENTER_CRITICAL();
			if (dsize != 0 && sent + ssize == tcb->sndcnt)
				tcb->tcpFlags |= PSH;
			OS_EXIT_CRITICAL();
	
			/*
			 * If this transmission includes previously transmitted data,
			 * snd.nxt will already be past snd.ptr. In this case,
			 * compute the amount of retransmitted data and keep score.
			 */
			if (seqLT(tcb->snd.ptr, tcb->snd.nxt))
				tcb->resent += min(tcb->snd.nxt - tcb->snd.ptr, ssize);
	
			tcb->snd.ptr += ssize;
			
			/* If this is the first transmission of a range of sequence
			 * numbers, record it so we'll accept acknowledgments
			 * for it later
			 */
			if (seqGT(tcb->snd.ptr, tcb->snd.nxt))
				tcb->snd.nxt = tcb->snd.ptr;
	
			/*
			 * Complete and prepend the TCP/IP headers.  Note that some IP
			 * fields are completed by the IP dispatcher and some are always
			 * zero for this TCP system. 
			 */
			if (tcb->backoff > 3) {
				/* Break point. */
				TCPDEBUG((LOG_WARNING, TL_TCP, "tcpOutput[%d]: Possible checksum problem",
							(int)(tcb - & tcbs[0])));
			}
			tcb->ipLen = hsize + dsize;
			tcb->ipIdent = IPNEWID();
			tcb->tcpHdrLen = (hsize - sizeof(IPHdr)) / 4;
			tcb->tcpCkSum = 0;
			nPREPEND(sBuf, (char *)&tcb->hdrCache, hsize);
			if (!sBuf) {
				TCPDEBUG((LOG_ERR, TL_TCP, "tcpOutput[%d]: Failed to write header",
							(int)(tcb - & tcbs[0])));
				break;
			}
			
			/*
			 * Prepare the header for the TCP checksum.  The TCP checksum is
			 * computed on a pseudo IP header as well as the TCP header and
			 * the data segment.  The pseudo IP header includes the length
			 * (not including the length of the IP header), protocol, source
			 * address and destination address fields.  Since the TTL is zeroed
			 * in the cache, we prepare this by loading the TCP datagram length
			 * in the IP checksum field.
			 */
			ipHdr = nBUFTOPTR(sBuf, IPHdr *);
			/* ipHdr->ip_ttl = 0; XXX TTL is zeroed in the header. */
			ipHdr->ip_sum = htons(ipHdr->ip_len - sizeof(IPHdr));
	
			/* Compute the checksum on the pseudo header. */
			tcpHdr = (TCPHdr *)(ipHdr + 1);		/* Assuming no IP options! */
			tcpHdr->ckSum = inChkSum(sBuf, sBuf->chainLen - 8, 8);
            
            /* Now that we've done the checksum, it's time to set the TTL. */
			ipHdr->ip_ttl = TCPTTL;
			
			/*
			 * If we're sending some data or flags, (re)start the 
			 * retransmission timer and, if it's not set, set the round-trip
			 * start time.
			 */
			if (ssize != 0) {
				tcb->retransTime = OSTimeGet()
					+ backOff(tcb->backoff) 
						* (2 * tcb->mdev + tcb->srtt + MSPERTICK) 
						/ MSPERTICK;
				TCPDEBUG((tcb->traceLevel + 1, TL_TCP,
							"tcpOutput[%d]: Timer %lu in %s bo=%u md=%lu srtt=%lu",
							(int)(tcb - & tcbs[0]),
							tcb->retransTime - OSTimeGet(), tcbStates[tcb->state],
							tcb->backoff, tcb->mdev, tcb->srtt));
				timeoutJiffy(&tcb->resendTimer, tcb->retransTime, resendTimeout, tcb);
	
				/*
				 * If round trip start time isn't set, set it to measure this
				 * segment.  Note that we depend on a time of zero being an
				 * extremely unlikely start time.
				 */
				if (!tcb->rttStart) {
					tcb->rttStart = mtime();
					tcb->rttseq = tcb->snd.ptr;
				}
			}
			
			/* We're finished messing with TCB variables so release the mutex. */
			OSSemPost(tcb->mutex);
			
			TCPDEBUG((tcb->traceLevel, TL_TCP, "tcpOutput[%d]: %s:%u->%s:%u %d@%lu",
						(int)(tcb - &tcbs[0]),
						ip_ntoa2(tcb->ipSrcAddr), ntohs(tcb->tcpSrcPort),
						ip_ntoa(tcb->ipDstAddr), ntohs(tcb->tcpDstPort),
						dsize, ntohl(tcb->tcpSeq)));
			TCPDEBUG((tcb->traceLevel, TL_TCP, "   out         %s %lu win %u",
						tcpFlagLabel[tcb->tcpFlags & TCPFLAGLABELMASK],
						ntohl(tcb->tcpAck),
						ntohs(tcb->tcpWin)));
			TCPDEBUG((tcb->traceLevel + 2, TL_TCP, "   out    IP: %.40H", (char *)ipHdr));
			TCPDEBUG((tcb->traceLevel + 2, TL_TCP, "   out   TCP: %.*H", 
						tcb->tcpHdrLen * 8, (char *)tcpHdr));
			if (dsize > 0) {
				TCPDEBUG((tcb->traceLevel, TL_TCP, "   out  DATA: %.*H",
							MIN(dsize, 20) * 2, (char *)ipHdr + hsize));
			}
						
			/* Pass the datagram to IP and we're done. */
			ipRawOut(sBuf);
			
			/* Grab the mutex again while we check for another segment. */
			OSSemPend(tcb->mutex, 0);
		}
		OSSemPost(tcb->mutex);
	}
}


/* 
 * tcpReset - Send an acceptable reset (RST) response for this segment.
 * The RST reply is composed in place on the input segment.
 */
static void tcpReset(
	NBuf *inBuf,				/* The input segment. */
	IPHdr *ipHdr,				/* The IP header in the segment. */
	TCPHdr *tcpHdr,				/* The TCP header in the segment. */
	u_int16_t segLen				/* The TCP segment length. */
)
{
	u_int16_t tmp16;
u_int32_t tmp32;
	char rflags;

	TCPDEBUG((LOG_INFO, TL_TCP, "tcpReset: to %s:%u from %s:%u %s len %u",
				ip_ntoa2(ipHdr->ip_src.s_addr), ntohs(tcpHdr->srcPort),
				ip_ntoa(ipHdr->ip_dst.s_addr), ntohs(tcpHdr->dstPort),
				tcpFlagLabel[tcpHdr->flags & TCPFLAGLABELMASK],
				inBuf->chainLen)); 
					
	if(tcpHdr->flags & RST)
		return;	/* Never send an RST in response to an RST */

	STATS(tcpStats.resetOut.val++;)

	/* Swap IP addresses and port numbers */
	tmp32 = ipHdr->ip_dst.s_addr;
	ipHdr->ip_dst.s_addr = ipHdr->ip_src.s_addr;
	ipHdr->ip_src.s_addr = tmp32;
	tmp16 = tcpHdr->dstPort;
	tcpHdr->dstPort = tcpHdr->srcPort;
	tcpHdr->srcPort = tmp16;

	rflags = RST;
	if(tcpHdr->flags & TH_ACK){
		/*
		 * This reset is being sent to clear a half-open connection.
		 * Set the sequence number of the RST to the incoming ACK
		 * so it will be acceptable.
		 */
		tcpHdr->seq = tcpHdr->ack;
		tcpHdr->ack = 0;
		NTOHL(tcpHdr->seq);
	} else {
		/*
		 * We're rejecting a connect request (SYN) from LISTEN state
		 * so we have to "acknowledge" their SYN.
		 */
		rflags |= TH_ACK;
		tcpHdr->ack = tcpHdr->seq;
		tcpHdr->seq = 0;
		if(tcpHdr->flags & TH_SYN)
			tcpHdr->ack++;
		tcpHdr->ack += segLen;
		if(tcpHdr->flags & TH_FIN)
			tcpHdr->ack++;
		NTOHL(tcpHdr->ack);
	}
	tcpHdr->flags = rflags;
	tcpHdr->win = 0;
	tcpHdr->urgent = 0;
	
	/*
	 * Prepare the header for the TCP checksum.  The TCP checksum is
	 * computed on a pseudo IP header as well as the TCP header and
	 * the data segment.  The pseudo IP header includes the length
	 * (not including the length of the IP header), protocol, source
	 * address and destination address fields.  Since the TTL is zeroed
	 * in the cache, we prepare this by loading the TCP datagram length
	 * in the IP checksum field.
	 */
	/* ipHdr->ip_ttl = 0; XXX TTL is zeroed in the header. */
	ipHdr->ip_sum = htons(ipHdr->ip_len - sizeof(IPHdr));
	
	tcpHdr->ckSum = 0;
	tcpHdr->ckSum = inChkSum(inBuf, inBuf->chainLen - 8, 8);
		
    /* Now that we've done the checksum, it's time to set the TTL. */
	ipHdr->ip_ttl = TCPTTL;
			
	/* Pass the datagram to IP and we're done. */
	ipRawOut(inBuf);
}


/*
 * trimSeg - Trim segment to fit window. 
 * Return the new segment length, -1 if segment is unaccepable.
 */
static int trimSeg(
	register TCPCB *tcb,
	register TCPHdr *tcpHdr,
	NBuf *nb,
	u_int hdrLen,
	u_int16_t segLen
)
{
	char accept = 0;                /* Assume segment is not acceptable. */
	u_int len = segLen;				/* Segment length including flags */
	int dupCnt;

	if(tcpHdr->flags & TH_SYN)
		len++;
	if(tcpHdr->flags & TH_FIN)
		len++;

	/* Acceptability tests */
	if(tcb->rcv.wnd == 0){
		/* 
		 * Only in-order, zero-length segments are acceptable when our window
		 * is closed.
		 */
		if(tcpHdr->seq == tcb->rcv.nxt && len == 0) {
			accept = !0;
		}
	} else {
		/* Some part of the segment must be in the window */
		if(inWindow(tcb, tcpHdr->seq)) {
			accept = !0;		/* Beginning is in. */
		} else if(len != 0){
			if(inWindow(tcb, (u_int32_t)(tcpHdr->seq + len - 1)) 
				|| seqWithin(tcb->rcv.nxt, tcpHdr->seq, 
				             (u_int32_t)(tcpHdr->seq + len - 1))) {
				accept = !0;	/* End is in or segment stradles window. */
			}
		}
	}
	
	/* Nothing to trim?*/
	if (!accept || len == 0) {
		;
		
	/* Trim leading edge. */
	} else if ((dupCnt = (int)(tcb->rcv.nxt - tcpHdr->seq)) > 0) {
		tcb->rerecv += dupCnt;
		/* Trim off SYN if present */
		if(tcpHdr->flags & TH_SYN){
			/* SYN is before first data byte */
			tcpHdr->flags &= ~TH_SYN;
			tcpHdr->seq++;
			dupCnt--;
		}
		/*
		 * We need to trim the duplicated data off the beginning of the segment.
		 * Start by splitting the headers from the segment, trim the segment,
		 * and then concatenate it back on after the headers.
		 */
		if(dupCnt > 0) {
			NBuf *n0;

			n0 = nSplit(nb, hdrLen);
			dupCnt = nTrim(NULL, &n0, dupCnt);
			nCat(nb, n0);
			tcpHdr->seq += dupCnt;
			segLen -= dupCnt;
		}
	}
	
	/* 
	 * Since we queue by buffer chain, we don't care about extra on the end. 
	 * XXX Of course this assumes that our maximum segment size (MSS) is small
	 * enough that we don't chew up too many buffers.
	 */
	
	return !accept ? -1 : segLen;
}


/* 
 * tcbHash - Return a hash code of a TCP/IP header for the hash chain header
 * array.
 */
static u_int tcbHash(Connection *conn)
{
	register u_int hval;

	/* Compute hash function on connection structure */
	hval = hiword(conn->remoteIPAddr);
	hval ^= loword(conn->remoteIPAddr);
	hval ^= hiword(conn->localIPAddr);
	hval ^= loword(conn->localIPAddr);
	hval ^= conn->remotePort;
	hval ^= conn->localPort;
	hval %= NTCB;
	return hval;
}

/* 
 * tcbLink - Insert TCB at head of proper hash chain and update the TCP/IP
 * header.
 */
static void tcbLink(register TCPCB *tcb)
{
	register TCPCB **tcbHead;

	if (tcb->prev == tcb) {
		TCPDEBUG((LOG_ERR, TL_TCP, "tcbLink: Attempt to link free TCB"));
	} else {
		if (tcb->next != tcb) {
			TCPDEBUG((LOG_INFO, TL_TCP, "tcbLink: Attempt to link linked TCB"));
			tcbUnlink(tcb);
		}
	
		OS_ENTER_CRITICAL();
		tcbHead = &tcbTbl[tcbHash(&tcb->conn)];
		if ((tcb->next = *tcbHead) != NULL)
			tcb->next->prev = tcb;
		*tcbHead = tcb;
		/* 
		 * Note that tcb->prev is already NULL since it was neither linked nor 
		 * free. 
		 */
		OS_EXIT_CRITICAL();
	}
}

/* 
 * tcbUnlink - Remove TCB from whatever hash chain it may be on.
 */
static void tcbUnlink(register TCPCB *tcb)
{
	register TCPCB **tcbHead;

	if (tcb->prev == tcb) {
		TCPDEBUG((LOG_ERR, TL_TCP, "tcbUnlink: Attempt to unlink free TCB"));
	} else if (tcb->next == tcb) {
		TCPDEBUG((LOG_INFO, TL_TCP, "tcbUnlink: Attempt to unlink unlinked TCB"));
	} else {
		OS_ENTER_CRITICAL();
		tcbHead = &tcbTbl[tcbHash(&tcb->conn)];
		if (*tcbHead == tcb)
			*tcbHead = tcb->next;	/* We're the first one on the chain */
		else if (tcb->prev)
			tcb->prev->next = tcb->next;
		if (tcb->next)
			tcb->next->prev = tcb->prev;
		tcb->next = tcb;			/* Next -> self => not linked. */
		tcb->prev = NULL;			/* Always NULL when neither free nor linked. */
		OS_EXIT_CRITICAL();
	}
}

/*
 * tcbLookup - Lookup connection, return TCB pointer or NULL if no match.
 */
static TCPCB * tcbLookup(Connection *conn)
{
	register TCPCB *tcb;

	tcb = tcbTbl[tcbHash(conn)];
	while(tcb) {
		if(conn->localIPAddr == tcb->conn.localIPAddr
			 && conn->remoteIPAddr == tcb->conn.remoteIPAddr
			 && conn->localPort == tcb->conn.localPort
			 && conn->remotePort == tcb->conn.remotePort)
			break;
		tcb = tcb->next;
	}
	return tcb;
}


/**********************************************
 * Functions to support devio interface.
 *********************************************/
/*
 * Validate that a TCP descriptor exists.  This is used on a device open.
 * Return the descriptor if valid, else -1.
 */
static INT tcpdValid(UINT tcpd)
{
	return (tcpd < MAXTCP) ? tcpd : -1;
}

