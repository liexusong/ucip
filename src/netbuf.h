/*****************************************************************************
* netbuf.h - Network Buffers header file.
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
*	Original based on BSD and ka9q mbufs.
******************************************************************************
* THEORY OF OPERATION
*
*	The network buffers (nBufs) form the basis for passing data between the
* protocols in the protocol stacks.  They are extensible in that they can be
* chained together when a data block is larger than the data area of a single
* buffer or if you need to prepend or append data that won't fit on the
* beginning or end (respectively) of a buffer.  This avoids expensive copy
* operations at the expense of consuming more memory.
*
*	This buffer structure is based on the mbuf structure in the BSD network
* codes except that it does not support clusters, types, or flags which were
* not needed in this stack.  Also, these are designed to be allocated from a
* static array rather than being malloc'd to avoid the overhead of heap memory
* management.  This design is for use in real-time embedded systems where the
* operating parameters are known beforehand and performance is critical.
*
*	To set up this buffer system, set the buffer size NBUFSZ in the header
* file and MAXNBUFS in the program file.  NBUFSZ should be set so that
* the link layer packets fit in a single buffer (normally).  You can monitor
* the minFreeBufs variable to ensure that your setting of MAXNBUFS is
* appropriate for your system.
*
*	Note that the prepend operation frees the current nBuf chain if it fails
* while the append operation does not.  This assumes that a prepend failure
* is catastrophic (if you can't add a header, you can't send it) while an
* append failure may mean that you send what you've got and try again.
*****************************************************************************/

#ifndef NETBUF_H
#define NETBUF_H


/*************************
*** PUBLIC DEFINITIONS ***
*************************/
/* 
 * By making NBUFSZ large enough to contain the largest mtu of all the
 * interfaces, no packet need ever be split across buffers.
 */
#define NBUFSZ 128				/* Max data size of an nBuf. */


/************************
*** PUBLIC DATA TYPES ***
************************/
/* The network buffer structure. */
typedef struct NBuf_s {
	struct	NBuf_s *nextBuf;	/* Next buffer in chain. */
	struct	NBuf_s *nextChain;	/* Next chain in queue. */
	char *	data;				/* Location of data. */
	u_int	len;				/* Bytes (octets) of data in this nBuf. */
	u_int	chainLen;			/* Total bytes in this chain - valid on top only. */
	u_long	sortOrder;			/* Sort order value for sorted queues. */
	char	body[NBUFSZ];		/* Data area of the nBuf. */
} NBuf;

/* The chain queue header structure. */
typedef struct NBufQHdr_s {
	NBuf	*qHead;				/* The first nBuf chain in the queue. */
	NBuf	*qTail;				/* The last nBuf chain in the queue. */
	u_int	qLen;				/* The number of chains in the queue. */
} NBufQHdr;

/* Network buffer statistics. */
typedef struct NBufStats_s {
	DiagStat headLine;			/* Headline text. */
	DiagStat curFreeBufs;		/* The current number of free nBufs. */
	DiagStat minFreeBufs;		/* The minimum number of free nBufs during operation. */
	DiagStat maxFreeBufs;		/* The maximum number of free nBufs during operation. */
	DiagStat maxChainLen;		/* Size of largest chain (from nChainLen). */
	DiagStat endRec;
} NBufStats;


/*****************************
*** PUBLIC DATA STRUCTURES ***
*****************************/
extern NBuf *topNBuf;
#if STATS_SUPPORT > 0
extern NBufStats nBufStats;
#else
extern u_int curFreeBufs;
#endif


/***********************
*** PUBLIC FUNCTIONS ***
***********************/
/* Initialize the memory buffer subsytem. */
void nBufInit (void);

/* nBUFTOPTR - Return nBuf's data pointer casted to type t. */
#define	nBUFTOPTR(n, t)	((t)((n)->data))

#if STATS_SUPPORT > 0
/* nBUFSFREE - Return the number of free buffers. */
#define nBUFSFREE() nBufStats.curFreeBufs.val
#else
#define nBUFSFREE() curFreeBufs
#endif

/*
 * nGET - Allocate an nBuf off the free list.
 * Return n pointing to new nBuf on success, n set to NULL on failure.
 */
#if STATS_SUPPORT > 0
#define	nGET(n) { \
	OS_ENTER_CRITICAL(); \
	if (((n) = topNBuf) != NULL) { \
		topNBuf = (n)->nextBuf; \
		(n)->nextBuf = NULL; \
		(n)->nextChain = NULL; \
		(n)->data = (n)->body; \
		(n)->len = 0; \
		(n)->chainLen = 0; \
		if (--nBufStats.curFreeBufs.val < nBufStats.minFreeBufs.val) \
			nBufStats.minFreeBufs.val = nBufStats.curFreeBufs.val; \
	} \
	OS_EXIT_CRITICAL(); \
}
#else
#define	nGET(n) { \
	OS_ENTER_CRITICAL(); \
	if (((n) = topNBuf) != NULL) { \
		topNBuf = (n)->nextBuf; \
		(n)->nextBuf = NULL; \
		(n)->nextChain = NULL; \
		(n)->data = (n)->body; \
		(n)->len = 0; \
		(n)->chainLen = 0; \
		--curFreeBufs; \
	} \
	OS_EXIT_CRITICAL(); \
}
#endif

/*
 * nFREE - Free a single nBuf and place the successor, if any, in out.
 * The value of n is invalid but unchanged.  If the buffer is already
 * free (nextChain references self), do nothing.
 *
 * nFree - Free a single nBuf and associated external storage.
 * Return the next nBuf in the chain, if any.
 *
 * nFreeChain - Free all nBufs in a chain.  
 * Return the next chain in the queue, if any.
 */
#if STATS_SUPPORT > 0
#define	nFREE(n, out) { \
	OS_ENTER_CRITICAL(); \
	if (n) { \
		if ((n)->nextChain == (n)) \
			panic("nFREE"); \
		else { \
			if (((out) = (n)->nextBuf) != NULL) \
				(out)->nextChain = (n)->nextChain; \
			(n)->nextBuf = topNBuf; \
			topNBuf = (n); \
			nBufStats.curFreeBufs.val++; \
		} \
	} else \
		(out) = NULL; \
	OS_EXIT_CRITICAL(); \
}
#else
#define	nFREE(n, out) { \
	OS_ENTER_CRITICAL(); \
	if (n) { \
		if ((n)->nextChain == (n)) \
			panic("nFREE"); \
		else { \
			if (((out) = (n)->nextBuf) != NULL) \
				(out)->nextChain = (n)->nextChain; \
			(n)->nextBuf = topNBuf; \
			topNBuf = (n); \
			curFreeBufs++; \
		} \
	} else \
		(out) = NULL; \
	OS_EXIT_CRITICAL(); \
}
#endif
NBuf *nFree(NBuf *n);
NBuf *nFreeChain(NBuf *n);

/*
 * nALIGN - Position the data pointer of a new nBuf so that it is len bytes
 * away from the end of the data area.
 */
#define	nALIGN(n, len) ((n)->data = (n)->body + NBUFSZ - (len))

/*
 * nADVANCE - Advance the data pointer of a new nBuf so that it is len bytes
 * away from the beginning of the data area.
 */
#define nADVANCE(n, len) ((n)->data = (n)->body + (len))

/*
 * nLEADINGSPACE - Return the amount of space available before the current
 * start of data in an nBuf.
 */
#define	nLEADINGSPACE(n) ((n)->len > 0 ? (n)->data - (n)->body : NBUFSZ)
	    
/*
 * nTRAILINGSPACE - Return the amount of space available after the end of data
 * in an nBuf.
 */
#define	nTRAILINGSPACE(n) (NBUFSZ - (u_int)((n)->data - (n)->body) - (n)->len)

/*
 * nPREPEND - Prepend plen bytes to nBuf n and load data from s if non-null.
 * Note that plen must be <= NBUFSZ.
 * If a new nBuf must be allocated but if allocation fails, the original nBuf chain
 * is freed and n is set to NULL.  Otherwise n is set to the new top of the chain.
 * Note that the chain length is updated but the chain is assumed to not be in
 * a queue.
 *
 * nPrepend - Same as above except return the new nBuf chain on success, NULL
 * on failure.
 */
#if STATS_SUPPORT > 0
#define	nPREPEND(n, s, plen) { \
	if (nLEADINGSPACE(n) >= (plen)) { \
		if ((n)->len) (n)->data -= (plen); \
		else (n)->data = (n)->body + NBUFSZ - (plen); \
		(n)->len += (plen); \
		if (((n)->chainLen += (plen)) > nBufStats.maxChainLen.val) \
			nBufStats.maxChainLen.val = (n)->chainLen; \
		if (s) memcpy((n)->data, (const char *)(s), (plen)); \
	} else \
		(n) = nPrepend((n), (const char *)(s), (plen)); \
}
#else
#define	nPREPEND(n, s, plen) { \
	if (nLEADINGSPACE(n) >= (plen)) { \
		if ((n)->len) (n)->data -= (plen); \
		else (n)->data = (n)->body + NBUFSZ - (plen); \
		(n)->len += (plen); \
		(n)->chainLen += (plen); \
		if (s) memcpy((n)->data, (const char *)(s), (plen)); \
	} else \
		(n) = nPrepend((n), (const char *)(s), (plen)); \
}
#endif
NBuf *nPrepend(
	NBuf	*n,					/* Destination nBuf chain. */
	const char *s,				/* The data to prepend. */
	u_int	plen				/* The length of the data to prepend. */
);


/*
 * nAPPEND - Append slen bytes to the nBuf chain n and load from s if non-null.
 * cLen is set to the number of bytes copied.  Note that the chain length is
 * updated but the chain is assumed to not be in a queue.
 *
 * nAPPENDCHAR - Append a single character to the nBuf chain.  cLen is set
 * to 1 on success, 0 on failure.  Note that c must be a legal lvalue so
 * that it's address may be passed to a function.
 *
 * nAppend - As above expect return the number of bytes copied.
 *
 * nAppendBuf - Append data from a source buffer chain starting from the offset
 * onto the end of the destination chain.  Return the number of characters
 * appended.
 *
 * nAppendFromQ - Append data from a source queue starting from the offset
 * onto the end of the destination chain.  Return the number of characters
 * appended.
 */
#if STATS_SUPPORT > 0
#define nAPPEND(n, s, sLen, cLen) { \
	if ((n)->nextBuf == NULL && nTRAILINGSPACE(n) >= (sLen)) { \
		(n)->len += (sLen); \
		if (((n)->chainLen += (sLen)) > nBufStats.maxChainLen.val) \
			nBufStats.maxChainLen.val = (n)->chainLen; \
		if (s) memcpy((n)->data, (s), (sLen)); \
		(cLen) = (sLen); \
	} else \
		(cLen) = nAppend((n), (s), (sLen)); \
}
#define nAPPENDCHAR(n, c, cLen) { \
	if ((n)->nextBuf == NULL && nTRAILINGSPACE(n) > 0) { \
		(n)->data[(n)->len++] = c; \
		if (++(n)->chainLen > nBufStats.maxChainLen.val) \
			nBufStats.maxChainLen.val = (n)->chainLen; \
		(cLen) = 1; \
	} else \
		(cLen) = nAppend((n), &(c), 1); \
}
#else
#define nAPPEND(n, s, sLen, cLen) { \
	if ((n)->nextBuf == NULL && nTRAILINGSPACE(n) >= (sLen)) { \
		(n)->len += (sLen); \
		(n)->chainLen += (sLen); \
		if (s) memcpy((n)->data, (s), (sLen)); \
		(cLen) = (sLen); \
	} else \
		(cLen) = nAppend((n), (s), (sLen)); \
}
#define nAPPENDCHAR(n, c, cLen) { \
	if ((n)->nextBuf == NULL && nTRAILINGSPACE(n) > 0) { \
		(n)->data[(n)->len++] = c; \
		(n)->chainLen++; \
		(cLen) = 1; \
	} else \
		(cLen) = nAppend((n), &(c), 1); \
}
#endif
u_int nAppend(NBuf *n, const char *s, u_int sLen);
u_int nAppendBuf(
	NBuf *nDst,					/* The destination chain. */
	NBuf *nSrc,					/* The source chain. */
	u_int off0, 				/* The starting offset into the source. */
	u_int len					/* The maximum bytes to copy. */
);
u_int nAppendFromQ(
	NBuf *nDst,					/* The destination chain. */
	NBufQHdr *nSrcQ,			/* The source queue. */
	u_int off0, 				/* The starting offset into the source. */
	u_int len					/* The maximum bytes to copy. */
);

/* nBufCopy - Return a new nBuf chain containing a copy of up to len bytes of
 * an nBuf chain starting "off0" bytes from the beginning.
 * Return the new chain on success, otherwise NULL. 
 */
NBuf *nBufCopy(
	NBuf *n,					/* Top of nBuf chain to be copied. */
	u_int off0, 				/* Offset into the nBuf chain's data. */
	u_int len					/* Maximum bytes to copy. */
);

/*
 * nPullup - Rearange an nBuf chain so that len bytes are contiguous and in
 * the data area of the buffer thereby allowing direct access to a structure
 * of size len. 
 * Return the resulting nBuf chain on success.  On failure, the original
 * nBuf is freed and NULL is returned.
 */
NBuf *nPullup(NBuf *n, u_int len);

/*
 * nCopyOut - Copy len bytes from an nBuf chain starting from an offset in
 * that chain.
 * Return the number of bytes copied.
 */
u_int nCopyOut(
	char *d, 					/* Destination string. */
	NBuf *n0, 					/* Source nBuf chain. */
	u_int off0, 				/* Offset into the nBuf chain's data. */
	u_int len					/* Max bytes to copy. */
);

/*
 * nSplit - Partition an nBuf chain in two pieces leaving len bytes in the
 * original chain.  A len of zero leaves an empty nBuf for n.  A len longer
 * than the amount of data in the chain returns NULL.
 * Return the new chain produced by the tail on success.  Otherwise, return
 * NULL and attempt to restore the chain to its original state.
 */
NBuf *nSplit(
	NBuf *n, 					/* The chain to be split. */
	u_int len					/* The bytes to leave in the original chain. */
);

/* 
 * nTrim - Trim up to len bytes from the chain, copying the data into
 * dst if dst is not NULL.  len > 0 trims off the front,
 * len < 0 trims off the end.  *nb is set to the new chain, NULL if
 * |len| >= the amount of data in the chain.
 * Note that this depends on the chain length field being accurate.
 * Return the actual number of bytes trimmed (always positive).
 *
 * nTrimQ - Trim bytes from the front of a buffer queue.
 * Note: The queue needs to be protected from collisions for the duration
 * of this call.
 * Return the number of bytes trimmed.
 */
int nTrim(char *dst, NBuf **nb, int len);
int nTrimQ(char *dst, NBufQHdr *qh, u_int len);


/*
 * nCat - Concatenate nBuf chain n2 to n1.  The chain length of n2 is added
 * to n1.
 * Return the new chain.
 */
NBuf *nCat(NBuf *n1, NBuf *n2);

/*
 * nChainLen - Determine the chain length of the mBuf chain and update the
 * chain length of the chain header.
 * Return the chain length.
 */
u_int nChainLen(NBuf *n);

/*
 * nENQUEUE - Add nBuf chain n to the end of the queue q.  q must be a
 * pointer to an nBufQHdr.  If any of them are NULL, nothing happens.
 *
 * nEnqSort - Insert a new chain into the queue in sorted order.
 * The sort function is designed to handle wrapping 32 bit values.
 * Return the number of chains in the queue on success, an error code
 * on error.
 */
#define nENQUEUE(q, n) \
	if ((n) && (q)) { \
		OS_ENTER_CRITICAL(); \
		if (!(q)->qTail) \
			(q)->qHead = (q)->qTail = (n); \
		else \
			(q)->qTail = ((q)->qTail->nextChain = n); \
		(q)->qLen++; \
		OS_EXIT_CRITICAL(); \
	}
int nEnqSort(NBufQHdr *qh, NBuf *nb, u_long sort);
		
    
/*
 * nDEQUEUE - Remove the first buffer chain, if any, from the queue q.
 * q must be a pointer to an nBufQHdr.  If q is NULL or empty, n is set to 
 * NULL.
 */
#define nDEQUEUE(q, n) { \
	OS_ENTER_CRITICAL(); \
	if (!(q) || !(q)->qHead) { \
		OS_EXIT_CRITICAL(); \
		(n) = NULL; \
	} else { \
		if (((q)->qHead = ((n) = (q)->qHead)->nextChain) == NULL) \
			(q)->qTail = NULL; \
		(q)->qLen--; \
		OS_EXIT_CRITICAL(); \
		(n)->nextChain = NULL; \
	} \
}

/*
 * nQHEAD - Returns a pointer to the first buffer chain in the queue.
 *
 * nQHEADSORT - Returns the sort value of the first buffer chain in the queue.
 */
#define nQHEAD(q) ((q) ? (q)->qHead : NULL)
#define nQHEADSORT(q) (((q) && (q)->qHead) ? (q)->qHead->sortOrder : 0)

/*
 * nQLENGTH - Returns the number of chains in the queue.
 */
#define nQLENGTH(q) ((q) ? (q)->qLen : 0)


#if DEBUG_SUPPORT > 0
/*
 * nDumpChain - Dump the details of the given buffer chain to the trace log.
 */
void nDumpChain(NBuf *n);
#endif

/*
 * inChkSum - Compute the internet ones complement 16 bit checksum for a given
 * length of a network buffer chain starting at offset off0.
 * Return the complement of the checksum in network byte order.
 */
u_short inChkSum(NBuf *nb, int len, int off0);

#endif
