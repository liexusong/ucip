/*****************************************************************************
* netppp.h - Network Point to Point Protocol header file.
*
* portions Copyright (c) 1997 Global Election Systems Inc.
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
* 97-11-05 Guy Lancaster <glanca@gesn.com>, Global Election Systems Inc.
*	Original derived from BSD codes.
*****************************************************************************/

#ifndef NETPPP_H
#define NETPPP_H

/* This depends on mbuf.h and net.h. */


/*************************
*** PUBLIC DEFINITIONS ***
*************************/
/* Configuration. */
#define DEFMRU	296		/* Try for this */
#define MINMRU	128		/* No MRUs below this */
#define MAXMRU	512		/* Normally limit MRU to this */

/* Error codes. */
#define PPPERR_PARAM -1				/* Invalid parameter. */
#define PPPERR_OPEN -2				/* Unable to open PPP session. */
#define PPPERR_DEVICE -3			/* Invalid I/O device for PPP. */
#define PPPERR_ALLOC -4				/* Unable to allocate resources. */
#define PPPERR_USER -5				/* User interrupt. */
#define PPPERR_CONNECT -6			/* Connection lost. */
#define PPPERR_AUTHFAIL -7			/* Failed authentication challenge. */
#define PPPERR_PROTOCOL -8			/* Failed to meet protocol. */

/*
 * PPP IOCTL commands.
 */
/*
 * Get the up status - 0 for down, non-zero for up.  The argument must
 * point to an int.
 */
#define PPPCTLG_UPSTATUS 100	// Get the up status - 0 down else up
#define PPPCTLS_ERRCODE 101		// Set the error code
#define PPPCTLG_ERRCODE 102		// Get the error code
#define	PPPCTLG_FD		103		// Get the fd associated with the ppp

/************************
*** PUBLIC DATA TYPES ***
************************/
/*
 * Statistics.
 */
typedef struct {
	DiagStat headLine;				/* Head line for display. */
    DiagStat ppp_ibytes;			/* bytes received */
    DiagStat ppp_ipackets;			/* packets received */
    DiagStat ppp_ierrors;			/* receive errors */
    DiagStat ppp_derrors;			/* dispatch errors */
    DiagStat ppp_obytes;			/* bytes sent */
    DiagStat ppp_opackets;			/* packets sent */
    DiagStat ppp_oerrors;			/* transmit errors */
} PPPStats;
#define PPPibytes	ppp_ibytes.val		/* bytes received */
#define PPPipackets	ppp_ipackets.val	/* packets received */
#define PPPierrors	ppp_ierrors.val		/* receive errors */
#define PPPderrors	ppp_derrors.val		/* dispatch errors */
#define PPPobytes	ppp_obytes.val		/* bytes sent */
#define PPPopackets	ppp_opackets.val	/* packets sent */
#define PPPoerrors	ppp_oerrors.val		/* transmit errors */

typedef struct {
    DiagStat vjs_packets;			/* outbound packets */
    DiagStat vjs_compressed;		/* outbound compressed packets */
    DiagStat vjs_searches;			/* searches for connection state */
    DiagStat vjs_misses;			/* times couldn't find conn. state */
    DiagStat vjs_uncompressedin;	/* inbound uncompressed packets */
    DiagStat vjs_compressedin;		/* inbound compressed packets */
    DiagStat vjs_errorin;			/* inbound unknown type packets */
    DiagStat vjs_tossed;			/* inbound packets tossed because of error */
} VJStats;


struct compstats {
    DiagStat unc_bytes;				/* total uncompressed bytes */
    DiagStat unc_packets;			/* total uncompressed packets */
    DiagStat comp_bytes;			/* compressed bytes */
    DiagStat comp_packets;			/* compressed packets */
    DiagStat inc_bytes;				/* incompressible bytes */
    DiagStat inc_packets;			/* incompressible packets */
    DiagStat ratio;					/* recent compression ratio << 8 */
};

struct ppp_comp_stats {
    struct compstats c;				/* packet compression statistics */
    struct compstats d;				/* packet decompression statistics */
};



/*****************************
*** PUBLIC DATA STRUCTURES ***
*****************************/
/* Buffers for outgoing packets. */
extern u_char outpacket_buf[NUM_PPP][PPP_MRU+PPP_HDRLEN];
#if STATS_SUPPORT > 0
extern PPPStats pppStats;			/* Statistics. */
#endif


/***********************
*** PUBLIC FUNCTIONS ***
***********************/

/* Initialize the PPP subsystem. */
void pppInit(void);

/*
 * Open a new PPP connection using the given I/O device.
 * This initializes the PPP control block but does not
 * attempt to negotiate the LCP session.
 * Return a new PPP connection descriptor on success or
 * an error code (negative) on failure. 
 */
int pppOpen(int fd);

/*
 * Close a PPP connection and release the descriptor. 
 * Any outstanding packets in the queues are dropped.
 * Return 0 on success, an error code on failure. 
 */
int pppClose(int pd);

/*
 * Send a packet on the given connection.
 * Return 0 on success, an error code on failure. 
 */
int pppOutput(int pd, u_short protocol, NBuf *nb);

/*
 * Process an mbuf chain received on given connection.
 * The mbuf chain is always passed on or freed making the original
 * parameter invalid.
 * Return 0 on success, an error code on failure. 
 */
int pppInput(int pd, NBuf *nb);

/*
 * Get and set parameters for the given connection.
 * Return 0 on success, an error code on failure. 
 */
int  pppIOCtl(int pd, int cmd, void *arg);

/*
 * Return the Maximum Transmission Unit for the given PPP connection.
 */
u_int pppMTU(int pd);

/*
 * Write n characters to a ppp link.
 *	RETURN: >= 0 Number of characters written
 *		 	 -1 Failed to write to device
 */
int pppWrite(int pd, const char *s, int n);

/* Configure i/f transmit parameters */
void ppp_send_config __P((int, int, u_int32_t, int, int));
/* Set extended transmit ACCM */
void ppp_set_xaccm __P((int, ext_accm *));
/* Configure i/f receive parameters */
void ppp_recv_config __P((int, int, u_int32_t, int, int));
/* Find out how long link has been idle */
int  get_idle_time __P((int, struct ppp_idle *));

/* Configure VJ TCP header compression */
int  sifvjcomp __P((int, int, int, int));
/* Configure i/f down (for IP) */
int  sifup __P((int));		
/* Set mode for handling packets for proto */
int  sifnpmode __P((int u, int proto, enum NPmode mode));
/* Configure i/f down (for IP) */
int  sifdown __P((int));	
/* Configure IP addresses for i/f */
int  sifaddr __P((int, u_int32_t, u_int32_t, u_int32_t));
/* Reset i/f IP addresses */
int  cifaddr __P((int, u_int32_t, u_int32_t));
/* Create default route through i/f */
int  sifdefaultroute __P((int, u_int32_t, u_int32_t));
/* Delete default route through i/f */
int  cifdefaultroute __P((int, u_int32_t, u_int32_t));

/* Get appropriate netmask for address */
u_int32_t GetMask __P((u_int32_t)); 

#endif
