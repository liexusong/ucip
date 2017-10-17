/*****************************************************************************
* nettcphd.h - Network Transmission Control Header Protocol header file.
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
* 98-03-02 Guy Lancaster <glanca@gesn.com>, Global Election Systems Inc.
*	Original based on ka9q and BSD codes.
******************************************************************************
* THEORY OF OPERATION
*
*****************************************************************************/

#ifndef NETTCPHDR_H
#define NETTCPHDR_H


/*************************
*** PUBLIC DEFINITIONS ***
**************************/
/*
 * TCP Header Flag Masks.
 */
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20

/* TCP header flag masks. */
#define	URG	0x20	/* URGent flag */
#ifdef ACK
#undef ACK
#define	ACK	0x10	/* ACKnowledgment flag */
#endif
#define	PSH	0x08	/* PuSH flag */
#define	RST	0x04	/* ReSeT flag */
#define	SYN	0x02	/* SYNchronize flag */
#define	FIN	0x01	/* FINal flag */



/************************
*** PUBLIC DATA TYPES ***
*************************/
typedef u_int32_t tcp_seq;

/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr {
	u_short	th_sport;		/* source port */
	u_short	th_dport;		/* destination port */
	tcp_seq	th_seq;			/* sequence number */
	tcp_seq	th_ack;			/* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN 
	u_char	th_x2:4,		/* (unused) */
		th_off:4;		/* data offset */
#endif
#if BYTE_ORDER == BIG_ENDIAN 
	u_char	th_off:4,		/* data offset */
		th_x2:4;		/* (unused) */
#endif
	u_char	th_flags;
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
	u_short	th_win;			/* window */
	u_short	th_sum;			/* checksum */
	u_short	th_urp;			/* urgent pointer */
};

/*
 * TCP header based on BSD codes modified for naming conventions.
 */
typedef struct TCPHdr_s {
	u_int16_t	srcPort;		/* source port */
	u_int16_t	dstPort;		/* destination port */
	u_int32_t	seq;			/* sequence number */
	u_int32_t	ack;			/* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN 
	u_char	th_x2:4,		/* (unused) */
			tcpOff:4;		/* data offset */
#elif BYTE_ORDER == BIG_ENDIAN 
	u_char	tcpOff:4,		/* data offset */
			th_x2:4;		/* (unused) */
#else
	ERROR: Byte order not defined!
#endif
	u_char	flags;
	u_int16_t	win;			/* window */
	u_int16_t	ckSum;			/* checksum */
	u_int16_t	urgent;			/* urgent pointer */
} TCPHdr;

/***********************
*** PUBLIC FUNCTIONS ***
************************/


#endif
