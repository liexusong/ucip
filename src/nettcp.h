/*****************************************************************************
* nettcp.h - Network Transmission Control Protocol header file.
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
* 98-02-02 Guy Lancaster <glanca@gesn.com>, Global Election Systems Inc.
*	Original based on ka9q and BSD codes.
******************************************************************************
* THEORY OF OPERATION
*
*****************************************************************************/

#ifndef NETTCP_H
#define NETTCP_H


/*************************
*** PUBLIC DEFINITIONS ***
**************************/
/*
 * TCP configuration. 
 */
#define	TCP_DEFMSS	256			/* Default maximum TCP segment size. */
#define TCP_MINMSS 256			/* Minimum MSS - interfaces must handle 296 - 40. */
#define	TCP_DEFWND	512			/* Default receiver window. */
#define	TCP_DEFRTT	500			/* Initial guess at round trip time (ms) */
#define TCP_ISSTHRESH 64*KILOBYTE-1	/* Initial slow start threshhold. */
#define TCP_DEFPORT 5000		/* Initial local port. */

#define TCP_MAXQUEUE 8			/* Maximum packets to allow in queue. */
#define TCP_MINSEG 80			/* Minimum sized segment for modified Nagle. */


/*
 * TCP Error codes.
 */
#define TCPERR_EOF -1			/* End of data. */
#define TCPERR_ALLOC -2			/* Unable to allocate a control block. */
#define TCPERR_PARAM -3			/* Invalid parameters. */
#define TCPERR_INVADDR -4		/* Invalid address. */
#define TCPERR_CONFIG -5		/* Invalid configuration. */
#define TCPERR_CONNECT -6		/* No connection. */
#define TCPERR_RESET -7			/* Connection reset received. */
#define TCPERR_TIMEOUT -8		/* Timeout on transmission. */
#define TCPERR_NETWORK -9		/* Network error - unreachable? */
#define TCPERR_PREC -10			/* IP Precedence error. */
#define TCPERR_PROTOCOL -11		/* Protocol error. */

/*
 * TCP IOCTL commands.
 */
/* Get an up status value - non-zero if connection is up. */
#define TCPCTLG_UPSTATUS 100
/* Get the bytes in the receive queue. */
#define TCPCTLG_RCVCNT 101
/*
 * Get/set the keepalive value in seconds - 0 for none.  The argument must
 * point to an int.  Note that if the connection is already established,
 * the keep alive timer won't be started until after the next transmission.
 */
#define TCPCTLG_KEEPALIVE 102
#define TCPCTLS_KEEPALIVE 103
/* Get/set the trace level.  For debugging use only. */
#define TCPCTLG_TRACELEVEL 104
#define TCPCTLS_TRACELEVEL 105


/*
 * TCP port numbers.
 */
#define	TCPPORT_ECHO		7		/* Echo data port */
#define	TCPPORT_DISCARD		9		/* Discard data port */
#define TCPPORT_TELNET		23		/* Telnet port */
#define TCPPORT_FINGER		79		/* Finger port */


/*
 * TCP option codes and lengths. 
 */
#define	TCPOPT_EOL				0
#define	TCPOPT_NOP				1
#define	TCPOPT_MAXSEG			2
#define TCPOLEN_MAXSEG			4
#define TCPOPT_WINDOW			3
#define TCPOLEN_WINDOW			3
#define TCPOPT_TIMESTAMP		8
#define TCPOLEN_TIMESTAMP		10


/************************
*** PUBLIC DATA TYPES ***
*************************/
typedef u_int32_t TCPAddress;
typedef u_int16_t TCPPort;

/* TCP statistics counters */
typedef struct TCPStats_s {
	DiagStat headLine;		/* Head line for display. */
	DiagStat curFree;		/* Current number of free control blocks. */
	DiagStat minFree;		/* Minimum number of free CB's during operation. */
	DiagStat runt;			/* Smaller than minimum size */
	DiagStat checksum;		/* TCP header checksum errors */
	DiagStat conout;		/* Outgoing connection attempts */
	DiagStat conin;			/* Incoming connection attempts */
	DiagStat resetOut;		/* Resets generated */
	DiagStat resetIn;		/* Resets received */
	DiagStat endRec;
} TCPStats;


/*****************************
*** PUBLIC DATA STRUCTURES ***
*****************************/
#if STATS_SUPPORT > 0
extern TCPStats tcpStats;
#endif


/***********************
*** PUBLIC FUNCTIONS ***
************************/

/*
 * Initialize the TCP subsystem.
 */
void tcpInit(void);

/* 
 * Return a new TCP descriptor on success or an error code (negative) on 
 * failure. 
 */
int tcpOpen(void);

/* 
 * Close a TCP connection and release the descriptor. 
 * Any outstanding packets in the queues are dropped.
 * Return 0 on success, an error code on failure. 
 */
int tcpClose(u_int td);

/*
 * Bind an IP address and port number in the sockaddr structure as our
 * address on a TCP connection.
 * Note: Currently the IP address must equal ourAddress since that is all
 * that ipDispatch() will recognize.
 * Return 0 on success, an error code on failure.
 */
int tcpBind(u_int td, struct sockaddr_in *myAddr);

/*
 * Establish a connection with a remote host.  Unless tcpBind() has been called,
 * the local IP address and port number are generated automatically.  
 * tcpConnect() blocks until the connection request either succeeds or fails.
 * tcpConnectMs() blocks up to the specified number of milliseconds.  
 * tcpConnectJiffy() blocks up to the specified number of Jiffies (OS timer 
 * ticks).
 * Return 0 on success, an error code on failure.
 */
#define tcpConnect(td, remoteAddr, tos) \
	tcpConnectJiffy(td, remoteAddr, tos, 0)
#define tcpConnectMs(td, remoteAddr, tos, t) \
	tcpConnectJiffy(td, remoteAddr, tos, (t + MSPERJIFFY - 1) / MSPERJIFFY)
int tcpConnectJiffy(u_int td, const struct sockaddr_in *remoteAddr, u_char tos, u_int timeout);

/*
 * tcpDisconnect - Tell the peer that we will not be sending any more data
 * (i.e. perform a half close on a connection).  tcpRead() will then
 * wait until the connection closes.
 * Return 0 when the peer acknowledges our message or an error code on
 * failure.
 */
int tcpDisconnect(u_int td);

/*
 * Set the number of backLog connections which will be queued to be picked up
 * by calls to accept.  Without this call, no connection will be opened until
 * tcpAccept() or tcpConnect() is called.
 * Return 0 on success, an error code on failure.
 */
int tcpListen(u_int td, int backLog);

/*
 * Pick up a connection opened by a remote host.  tcpBind() must be used to
 * specify the local address and port number for the connection.  Unless 
 * tcpListen() has been called, no connection will be accepted until this
 * is called.
 * Return a new TCP descriptor for the opened connection on success, an
 * error code on failure.
 */
#define tcpAccept(td, peerAddr) \
	tcpAcceptJiffy(td, peerAddr, 0)
#define tcpAcceptMs(td, peerAddr, t) \
	tcpReadJiffy(td, peerAddr, (t + MSPERJIFFY - 1) / MSPERJIFFY)
int tcpAcceptJiffy(u_int td, struct sockaddr_in *peerAddr, u_int timeout);

/*
 * Read from a connected TCP connection.  tcpRead() blocks until at least
 * one character is read or an error occurs.  tcpReadMs() blocks at most
 * the specified number of milliseconds.  tcpReadJiffy() blocks at most
 * the specified number of Jiffies (OS timer ticks).
 * Return the number of bytes read on success or timeout, an error code on
 * failure. 
 */
int tcpRead(u_int td, void *s, u_int len);
#define tcpReadMs(td, s, len, t) \
	tcpReadJiffy(td, s, len, (t + MSPERJIFFY - 1) / MSPERJIFFY)
int tcpReadJiffy(u_int td, void *s, u_int len, u_int timeout);

/*
 * Write to a connected TCP connection.  tcpWrite() blocks until all bytes
 * have been queued or an error occurs.  tcpWriteMs() blocks at most the
 * specified number of milliseconds.  tcpWriteJiffy() blocks at most the
 * specified number of Jiffies (OS timer ticks).
 * Return the number of bytes written on success or timeout, an error code
 * on failure.
 */
int tcpWrite(u_int td, const void *s, u_int n);
#define tcpWriteMs(td, s, n, t) \
	tcpWriteJiffy(td, s, n, (t + MSPERJIFFY - 1) / MSPERJIFFY)
int tcpWriteJiffy(u_int td, const void *s, u_int n, u_int timeout);

/*
 * tcpWait - Wait for the connection to be closed.  Normally this will be
 * done after a disconnect before trying to reuse the TCB.  This will fail
 * if the connection is not closing.
 * Returns 0 on success or an error code if the connection is not
 * closing.
 */
int tcpWait(u_int td);

/* 
 * Receive an incoming datagram.  This is called from IP.
 */
void tcpInput(NBuf *inBuf, u_int ipHeadLen);

/* 
 * Get and set parameters for the given connection.
 * Return 0 on success, an error code on failure. 
 */
int  tcpIOCtl(u_int td, int cmd, void *arg);

#endif
