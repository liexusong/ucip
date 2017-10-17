/*****************************************************************************
* netbuf.c - Network Buffers program file.
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
* 98-01-30 Guy Lancaster <glanca@gesn.com>, Global Election Systems Inc.
*	Original based on BSD codes.
******************************************************************************
* PROGRAMMER NOTES
*
* FREE BUFFER MARK
*	Free buffers have nextChain pointing back to themselves.
*
* CRITICAL SECTIONS
*	Only queue operations are protected from corruption from other tasks and
* interrupts.  It is assumed that only one task at a time operates on a buffer
* chain but multiple tasks will share queues.
*
* BUFFER QUEUES
*	The buffer queue structure's primary purpose is to minimize the overhead
* of adding a new chain to the queue.  A side benefit is that if packets
* span more than one nBuf, then the overhead to seek to a particular offset
* in the queue is reduced.  A queue is required to maintain boundaries of 
* incoming UDP datagrams if UDP support were added.
*****************************************************************************/

#include "netconf.h"
#include "net.h"
#include "netbuf.h"

#include <stdio.h>
#include "netdebug.h"


/*************************/
/*** LOCAL DEFINITIONS ***/
/*************************/
#define MAXNBUFS 32					/* The number of nBufs allocated. */

                                                                    
/******************************/
/*** PUBLIC DATA STRUCTURES ***/
/******************************/
NBuf *topNBuf;
#if STATS_SUPPORT > 0
NBufStats nBufStats;
#else
u_int curFreeBufs;
#endif


/*****************************/
/*** LOCAL DATA STRUCTURES ***/
/*****************************/
/* The free list of buffers. */
static NBuf nBufs[MAXNBUFS];


/***********************************/
/*** PUBLIC FUNCTION DEFINITIONS ***/
/***********************************/
/* Initialize the memory buffer subsytem. */
void nBufInit (void)
{
	int i;
	
	topNBuf = &nBufs[0];
	for (i = 0; i < MAXNBUFS; i++) {
		nBufs[i].nextBuf = &nBufs[i + 1];
		nBufs[i].nextChain = &nBufs[i];
	}
	nBufs[MAXNBUFS - 1].nextBuf = NULL;
	
#if STATS_SUPPORT > 0
	memset(&nBufStats, 0, sizeof(nBufStats));
	nBufStats.headLine.fmtStr    = "\t\tNETWORK BUFFERS\r\n";
	nBufStats.curFreeBufs.fmtStr = "\tCURRENT FREE: %5lu\r\n";
	nBufStats.curFreeBufs.val = MAXNBUFS;
	nBufStats.minFreeBufs.fmtStr = "\tMINIMUM FREE: %5lu\r\n";
	nBufStats.minFreeBufs.val = MAXNBUFS;
	nBufStats.maxFreeBufs.fmtStr = "\tMAXIMUM FREE: %5lu\r\n";
	nBufStats.maxFreeBufs.val = MAXNBUFS;
	nBufStats.maxChainLen.fmtStr = "\tMAX CHAIN SZ: %5lu\r\n";
#else
	curFreeBufs = MAXNBUFS;
#endif
}

/*
 * nFree - Free a single nBuf and associated external storage.
 * Return the next nBuf in the chain, if any.
 */
NBuf *nFree(NBuf *n)
{
	NBuf *n0;
	
	nFREE(n, n0)
	return n0;
}


/*
 * nFreeChain - Free all nBufs in a chain.  
 * Return the next chain in the queue, if any.
 */
NBuf *nFreeChain(NBuf *n)
{
	NBuf *n0, *n1;
	
	if (n) {
		if (n->nextChain == n)
			panic("nFreeChain");
		else {
			n0 = n;
			n = n->nextChain;
			while (n0) {
				nFREE(n0, n1);
				n0 = n1;
			}
		}
	}
	
	return n;
}


/*
 * nPrepend - Prepend plen bytes to nBuf n and load from s if non-null.
 * A new nBuf is always allocated but if allocation fails, the
 * original nBuf chain is freed.  The chain size is updated.  This assumes
 * that the chain is not in a queue.
 * Return the new nBuf chain on success, NULL on failure.
 */
NBuf *nPrepend(
	NBuf	*n,					/* Destination nBuf chain. */
	const char *s,				/* The data to prepend. */
	u_int	plen				/* The length of the data to prepend. */
)
{
	NBuf *n0;
	
	if (n) {
		nGET(n0);
		while (n0) {
			n0->nextBuf = n;
			if (plen > NBUFSZ) {
				n0->len = NBUFSZ;
#if STATS_SUPPORT > 0
				if ((n0->chainLen = n->chainLen + NBUFSZ) > nBufStats.maxChainLen.val)
					nBufStats.maxChainLen.val = n0->chainLen;
#else
				n0->chainLen = n->chainLen + NBUFSZ;
#endif
				if (s) {
					memcpy(n0->data, s + plen - NBUFSZ, NBUFSZ);
				}
				plen -= NBUFSZ;
				n = n0;
				nGET(n0);
			} else {
				n0->len = plen;
#if STATS_SUPPORT > 0
				if ((n0->chainLen = n->chainLen + plen) > nBufStats.maxChainLen.val)
					nBufStats.maxChainLen.val = n0->chainLen;
#else
				n0->chainLen = n->chainLen + plen;
#endif
				n0->data = n0->body + NBUFSZ - plen;
				if (s) {
					memcpy(n0->data, s, plen);
				}
				plen = 0;
				n = n0;
				/*** We're done, skip the test.
				n0 = NULL;
				***/
				break;
			}
		}
		if (plen) {
			NBUFDEBUG((LOG_ERR, "nPrepend: No free buffers"));
			(void)nFreeChain(n);
			n = NULL;
		}
	}
	return n;
}


/*
 * nAppend - Append slen bytes to the nBuf chain n and load from s if non-null.
 * Note that the chain length is updated but the chain is assumed to not be in
 * a queue.
 * Return the number of bytes appended.
 */
u_int nAppend(NBuf *n, const char *s, u_int sLen)
{
	u_int copied = 0, i;
	NBuf *n0 = n;	

	if (n0 && sLen) {
		/* Find the last nBuf on the chain. */
		for (; n0->nextBuf; n0 = n0->nextBuf);
		/* If there's space, append what we can. */
		if ((i = (u_int)nTRAILINGSPACE(n0)) > 0) {
			if (i > sLen)
				i = sLen;
			n0->len += i;
#if STATS_SUPPORT > 0
			if ((n->chainLen += i) > nBufStats.maxChainLen.val)
				nBufStats.maxChainLen.val = n->chainLen;
#else
			n->chainLen += i;
#endif
			if (s) {
				memcpy(n0->data, s, i);
				s += i;
			}
			copied = i;
			sLen -= i;
		}
		if (sLen) {
			nGET(n0->nextBuf);
			n0 = n0->nextBuf;
		}
	}
	/* Append new buffers until s is consumed or we fail to allocate. */
	while (n0 && sLen) {
		if (sLen > NBUFSZ) {
			n0->len = NBUFSZ;
#if STATS_SUPPORT > 0
			if ((n->chainLen += NBUFSZ) > nBufStats.maxChainLen.val)
				nBufStats.maxChainLen.val = n->chainLen;
#else
			n->chainLen += NBUFSZ;
#endif
			if (s) {
				memcpy(n0->data, s, NBUFSZ);
				s += NBUFSZ;
			}
			sLen -= NBUFSZ;
			copied += NBUFSZ;
		} else {
			n0->len = sLen;
#if STATS_SUPPORT > 0
			if ((n->chainLen += sLen) > nBufStats.maxChainLen.val)
				nBufStats.maxChainLen.val = n->chainLen;
#else
			n->chainLen += sLen;
#endif
			if (s) {
				memcpy(n0->data, s, sLen);
			}
			copied += sLen;
			break;	/* We're done, skip the test. */
		}
		nGET(n0->nextBuf);
		n0 = n0->nextBuf;
	}
	return copied;
}


/*
 * nAppendBuf - Append data from buffer chain n1 starting from the offset
 * onto the end of the chain n0.  
 * Return the number of characters appended.
 */
u_int nAppendBuf(
	NBuf *nDst,					/* The destination chain. */
	NBuf *nSrc,					/* The source chain. */
	u_int off0, 				/* The starting offset into the source. */
	u_int len					/* The maximum bytes to copy. */
)
{
	u_int st = 0, copySz;
	NBuf *nTop = nDst, *nTmp;
	
	if (!nDst)
		return 0;
		
	/* Find the end of the destination chain. */
	nTop = nDst;
	for (; nDst->nextBuf; nDst = nDst->nextBuf)
		;
		
	/* Find the starting position in the source chain. */
	for (; nSrc && off0 > nSrc->len; nSrc = nSrc->nextBuf)
		off0 -= nSrc->len;
	
	if (nSrc) {
		while (nDst && len) {
			/* Compute how much to copy from the current source buffer. */
			copySz = min(len, nSrc->len - off0);

			/* Do we need to append another destination buffer? */
			/* 
			 * Note that we don't attempt to fill small spaces at the
			 * end of the current destination buffer since on average,
			 * we don't expect that it would reduce the number of
			 * buffers used and it would complicate and slow the 
			 * operation.
			 */
			if (nTRAILINGSPACE(nDst) < copySz) {
				nGET(nTmp);
				if (!nTmp) {
					NBUFDEBUG((LOG_ERR, "nBufCopy: No free buffers"));
					nDst = NULL;
					break;
				}
				nDst->nextBuf = nTmp;
				nDst = nTmp;
			}
				
			/* Copy it and advance to the next source buffer if needed. */
			memcpy(&nDst->data[nDst->len], &nSrc->data[off0], copySz);
#if STATS_SUPPORT > 0
			if ((nTop->chainLen += copySz) > nBufStats.maxChainLen.val)
				nBufStats.maxChainLen.val = nTop->chainLen;
#else
			nTop->chainLen += copySz;
#endif
			nDst->len += copySz;
			st += copySz;
			len -= copySz;
			off0 = 0;
			nSrc = nSrc->nextBuf;
		}
	}
	
	return st;
}


/*
 * nAppendFromQ - Append data from a source queue starting from the offset
 * onto the end of the destination chain.
 * Return the number of characters appended.
 */
u_int nAppendFromQ(
	NBuf *nDst,					/* The destination chain. */
	NBufQHdr *nSrcQ,			/* The source queue. */
	u_int off0, 				/* The starting offset into the source. */
	u_int len					/* The maximum bytes to copy. */
)
{
	u_int st = 0, copySz;
	NBuf *nDstTop, *nSrc, *nSrcTop, *nTmp;
	
	/* Validate parameters. */
	if (!nDst || !nSrcQ)
		return 0;
	
	/* Find the end of the destination chain. */
	nDstTop = nDst;
	while (nDst->nextBuf)
		nDst = nDst->nextBuf;
		
	/* Find the starting chain in the source queue. */
	for (nSrc = nSrcQ->qHead; nSrc && off0 >= nSrc->chainLen; nSrc = nSrc->nextChain) {
		off0 -= nSrc->chainLen;
	}
	nSrcTop = nSrc;
	
	/* Find the starting position in the source chain. */
	for (; nSrc && off0 >= nSrc->len; nSrc = nSrc->nextBuf) {
		off0 -= nSrc->len;
	}

	while (nSrc && nDst && len) {
		/* 
		 * Compute how much to copy from the current source buffer. 
		 * Note that since we copy from a single source buffer at a
		 * time, we don't have to check that the copy size fits in
		 * a single buffer.
		 */
		copySz = min(len, nSrc->len - off0);

		/* Append another destination buffer if needed. */
		/* 
		 * Note that we don't attempt to fill small spaces at the
		 * end of the current destination buffer since on average,
		 * we don't expect that it would reduce the number of
		 * buffers used and it would complicate and slow the 
		 * operation.
		 */
		if (nTRAILINGSPACE(nDst) < copySz) {
			nGET(nTmp);
			if (!nTmp) {
				NBUFDEBUG((LOG_ERR, "nAppendFromQ: No free buffers"));
				nDst = NULL;
				break;
			}
			nDst->nextBuf = nTmp;
			nDst = nTmp;
		}
			
		/* Copy it and advance to the next source buffer if needed. */
		memcpy(&nDst->data[nDst->len], &nSrc->data[off0], copySz);
#if STATS_SUPPORT > 0
		if ((nDstTop->chainLen += copySz) > nBufStats.maxChainLen.val)
			nBufStats.maxChainLen.val = nDstTop->chainLen;
#else
		nDstTop->chainLen += copySz;
#endif
		nDst->len += copySz;
		st += copySz;
		len -= copySz;
		off0 = 0;
		if ((nSrc = nSrc->nextBuf) == NULL)
			nSrc = nSrcTop = nSrcTop->nextChain;
			
	}
	
	return st;
}


/*
 * nBufCopy - Return a new nBuf chain containing a copy of up to len bytes of
 * an nBuf chain starting "off0" bytes from the beginning.
 * Return the new chain on success, otherwise NULL. 
 */
NBuf *nBufCopy(
	NBuf *nSrc,					/* Top of nBuf chain to be copied. */
	u_int off0, 				/* Offset into the nBuf chain's data. */
	u_int len					/* Maximum bytes to copy. */
)
{
	u_int i;
	NBuf *nTop = NULL, *nDst, *nTmp;
	
	/* Find the starting position in the source chain. */
	for (; nSrc && off0 > nSrc->len; nSrc = nSrc->nextBuf)
		off0 -= nSrc->len;
	
	if (nSrc) {
		nGET(nDst);
		nTop = nDst;
		
		while (nDst && len) {
			/* Compute how much to copy from the current source buffer. */
			i = nSrc->len - off0;
			if (i > len)
				i = len;
			
			/* Copy it and advance to the next buffer if needed. */
			memcpy(nDst->data, &nSrc->data[off0], i);
#if STATS_SUPPORT > 0
			if ((nTop->chainLen += i) > nBufStats.maxChainLen.val)
				nBufStats.maxChainLen.val = nTop->chainLen;
#else
			nTop->chainLen += i;
#endif
			nDst->len = i;
			len -= i;
			off0 = 0;
			nSrc = nSrc->nextBuf;
			if (len && nSrc) {
				nGET(nTmp);
				if (nTmp) {
					nDst->nextBuf = nTmp;
					nDst = nTmp;
				} else {
					NBUFDEBUG((LOG_ERR, "nBufCopy: No free buffers"));
					(void)nFreeChain(nTop);
					nTop = NULL;
				}
			} else {
				/*** Let's just break out...
				nDst = NULL;
				***/
				break;
			}
		}
	}
	return nTop;
}


/*
 * nPullup - Rearange an nBuf chain so that len bytes are contiguous and in
 * the data area of the buffer thereby allowing direct access to a structure
 * of size len. 
 * Return the resulting nBuf chain on success.  On failure, the original
 * nBuf is freed and NULL is returned.
 */
NBuf *nPullup(NBuf *nIn, u_int len)
{
	char *s, *d;
	u_int i;
	NBuf *nTmp, *nPrev, *nNext;
	
	if (!nIn)
		;
	/* If the required data is already in the first buffer, we're done! */
	else if (nIn->len >= len)
		;
	/* If the required data won't fit in the first buffer, fail! */
	else if (len > NBUFSZ) {
		(void)nFreeChain(nIn);
		nIn = NULL;
	} else {
		/* If there's not enough space at the end, shift the data to the beginning. */
		if (nTRAILINGSPACE(nIn) < len) {
			s = nBUFTOPTR(nIn, char *);
			d = nIn->data = &nIn->body[0];
			for (i = nIn->len; i > 0; i--)
				*d++ = *s++;
		}
		/* Move the data in from successive buffers. */
		nPrev = nIn;
		nNext = nIn->nextBuf;
		while (len && nNext) {
			i = min(len, nNext->len);
			memcpy(&nIn->data[nIn->len], nNext->data, i);
			nIn->len += i;
			/* If this emptied the buffer, free it. */
			if ((nNext->len -= i) == 0) {
				nTmp = nNext;
				nFREE(nTmp, nNext);
				nPrev->nextBuf = nNext;
			} else {
				nNext->data += i;
			}
			len -= i;
			nPrev = nNext;
			nNext = nNext->nextBuf;
		}
	}
	return nIn;
}


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
)
{
	u_int copied = 0, i;
	NBuf *nNext;
	
	/* Find the starting position in the original chain. */
	for (nNext = n0; nNext && off0 > nNext->len; nNext = nNext->nextBuf)
		off0 -= nNext->len;
	
	while (len && nNext) {
		i = min(len, nNext->len - off0);
		memcpy(&d[copied], &nNext->data[off0], i);
		off0 = 0;
		copied += i;
		len -= i;
		nNext = nNext->nextBuf;
	}
	
	return copied;
}

/*
 * nSplit - Partition an nBuf chain in two pieces leaving len bytes in the
 * original chain.  A len of zero leaves an empty nBuf for n0.  A len longer
 * than the amount of data in the chain returns NULL.
 * Return the new chain produced by the tail on success.  Otherwise, return
 * NULL and attempt to restore the chain to its original state.
 */
NBuf *nSplit(
	NBuf *n0, 					/* The chain to be split. */
	u_int len					/* The bytes to leave in the original chain. */
)
{
	NBuf *n1 = NULL, *nNext;
	u_int off0 = len;
	
	/* Find the starting position in the original chain. */
	for (nNext = n0; nNext && len > nNext->len; nNext = nNext->nextBuf)
		len -= nNext->len;
	
	/* If the chain is too short, return nothing. */
	if (!nNext)
		;
	/* If the chain breaks on the desired boundary, trivial case. */
	else if (len == nNext->len) {
		n1 = nNext->nextBuf;
		nNext->nextBuf = NULL;
		n1->chainLen = n0->chainLen - off0;
		n0->chainLen = off0;
	}
	/* Otherwise we need to split this next buffer. */
	else {
		nGET(n1);
		if (n1) {
			n1->len = nNext->len - len;
			n1->nextBuf = nNext->nextBuf;
			nNext->nextBuf = NULL;
			/* Move the data to the end of the new buffer to leave space for
			 * new headers. */
			n1->data = &n1->body[NBUFSZ - n1->len];
			memcpy(n1->data, &n0->data[len], n1->len);
			n0->len -= n1->len;
			n1->chainLen = n0->chainLen - off0;
			n0->chainLen = off0;
		}
		/* If !n1, we return NULL. */
	}
	
	return n1;
}


/* 
 * nTrim - Trim up to len bytes from the chain, copying the data into
 * dst if dst is not NULL.  len > 0 trims off the front,
 * len < 0 trims off the end.  *nb is set to the new chain, NULL if
 * |len| >= the amount of data in the chain.
 * Note that this depends on the chain length field being accurate.
 * Return the actual number of bytes trimmed (always positive).
 */
int nTrim(char *dst, NBuf **nb, int len)
{
	int st = 0;
	NBuf *n0, *n1;
	u_int cLen;				/* Total chain length. */
	
	if (!len || !nb || !(*nb))
		;
	else if (len > 0) {
		n0 = *nb;
		cLen = n0->chainLen;
		
		/* Trim whole leading buffers. */
		while (n0 && len >= n0->len) {
			st += n0->len;
			len -= n0->len;
			cLen -= n0->len;
			if (dst) {
				memcpy(dst, n0->data, n0->len);
				dst += n0->len;
			}
			nFREE(n0, n1);
			n0 = n1;
		}
		/* Trim partial buffers. */
		if (n0) {
			if (len) {
				st += len;
				cLen -= len;
				if (dst) {
					memcpy(dst, n0->data, len);
				}
				n0->data += len;
				n0->len -= len;
			}
			n0->chainLen = cLen;
		}
		*nb = n0;
	} else {
		len = -len;
		n0 = *nb;
		cLen = n0->chainLen;
		if (cLen > len) {
			n1 = nSplit(n0, cLen - len);
		} else {
			n1 = n0;
			n0 = NULL;
		}
		st = nTrim(dst, &n1, len);
		*nb = n0;
	}
	
	return st;
}

/*
 * nTrimQ - Trim bytes from the front of a buffer queue.
 * Note: The queue needs to be protected from collisions for the duration
 * of this call.
 * Return the number of bytes trimmed.
 */
int nTrimQ(char *dst, NBufQHdr *qh, u_int len)
{
	int st = 0;
	
	if (qh && qh->qHead && len) {
		NBuf *n0;
		int trimmed;
		
		/* Trim entire chains. */
#ifdef XXX
		OS_ENTER_CRITICAL();
#endif
		while (qh->qHead && len >= qh->qHead->chainLen) {
			if ((qh->qHead = (n0 = qh->qHead)->nextChain) == NULL)
				qh->qTail = NULL;
			qh->qLen--;
#ifdef XXX
			OS_EXIT_CRITICAL();
#endif
			
			n0->nextChain = NULL;
			trimmed = nTrim(dst, &n0, len);
			if (dst)
				dst += trimmed;
			len -= trimmed;
			st += trimmed;
#ifdef XXX
			OS_ENTER_CRITICAL();
#endif
		}
		
		/* If more to go, trim from next chain. */
		if (len && qh->qHead) {
			/* 
			 * XXX LONG CRITICAL SECTION!!!  Could we pop this off the queue,
			 * trim it, and then replace the remainder?  Do we need a semaphore? 
			 */
			trimmed = nTrim(dst, &qh->qHead, len);
			st += trimmed;
		}
#ifdef XXX
		OS_EXIT_CRITICAL();
#endif
	}
	
	return st;
}


/*
 * nCat - Concatenate nBuf chain n2 to n1.  The chain length of n2 is added
 * to n1.
 * Return the new chain.
 */
NBuf *nCat(NBuf *n1, NBuf *n2)
{
	NBuf *nNext;
	
	if (!n1 || !n2)
		;
	else {
		for (nNext = n1; nNext->nextBuf; nNext = nNext->nextBuf)
			;
		nNext->nextBuf = n2;
#if STATS_SUPPORT > 0
		if ((n1->chainLen += n2->chainLen) > nBufStats.maxChainLen.val)
			nBufStats.maxChainLen.val = n1->chainLen;
#else
		n1->chainLen += n2->chainLen;
#endif
	}
	
	return n1;
}


/*
 * nChainLen - Determine the chain length of the mBuf chain and update the
 * chain length field of the top buffer.
 * Return the chain length.
 */
u_int nChainLen(NBuf *n)
{
	u_int chainLen = 0;
	NBuf *nNext;
	
	for (nNext = n; nNext; nNext = nNext->nextBuf)
		chainLen += nNext->len;
	n->chainLen = chainLen;
#if STATS_SUPPORT > 0
	if (chainLen > nBufStats.maxChainLen.val)
		nBufStats.maxChainLen.val = chainLen;
#endif

	return chainLen;
}


/*
 * nEnqSort - Insert a new chain into the queue in sorted order.
 * The sort function is designed to handle wrapping 32 bit values.
 * Return the number of chains in the queue on success, an error code
 * on error.
 */
int nEnqSort(NBufQHdr *qh, NBuf *nb, u_int32 sort) 
{
	int st;
	
	OS_ENTER_CRITICAL();
	if (!qh || !nb)
		st = -1;
	else if (!qh->qHead) {
		qh->qHead = qh->qTail = nb;
		nb->nextChain = NULL;
		st = qh->qLen = 1;
	} else {
		NBuf *n0;
		/*** NOTE: Potentially long critical section. ***/
		for(n0 = qh->qHead; 
			n0->nextChain && (long)(sort - nb->sortOrder) >= 0;
			n0 = n0->nextChain)
			;
		nb->nextChain = n0->nextChain;
		n0->nextChain = nb;
		st = ++qh->qLen;
	}
	OS_EXIT_CRITICAL();
	
	return st;
}
		
#if DEBUG_SUPPORT > 0
/*
 * nDumpChain - Dump the details of the given buffer chain to the trace log.
 */
void nDumpChain(NBuf *n)
{
	int bufNum, len, dLen;
	u_char *dPtr;
	
	trace(LOG_INFO, "Buffer chain len=%u", n->chainLen);
	for (bufNum = 0; n; bufNum++) {
		dPtr = nBUFTOPTR(n, u_char *);
		for (len = n->len; len > 0;) {
			dLen = MIN(len, 32);
			trace(LOG_INFO, "Buf %d[%d]:%.*H", bufNum, dLen, dLen * 2, dPtr);
			len -= dLen;
			dPtr += dLen;
		}
		n = n->nextBuf;
	}
}
#endif

/*
 * inChkSum - Compute the internet ones complement 16 bit checksum for a given
 * length of a network buffer chain starting at offset off0.
 * Return the checksum in network byte order.
 */
#define ADDCARRY(x)  (x > 65535 ? x -= 65535 : x)
#define REDUCE {l_util.l = sum; sum = (u_long)l_util.s[0] + (u_long)l_util.s[1]; ADDCARRY(sum);}
u_short inChkSum(NBuf *nb, int len, int off0)
{
	register u_short *w;
	register long sum = 0;
	register int bufLen = 0;
	register NBuf *n0 = nb;
	int byte_swapped = 0;

	union {
		char	c[2];
		u_short	s;
	} s_util;
	union {
		u_short s[2];
		long	l;
	} l_util;

	/* Ensure that there is enough data for the offset. */
	if (nb->len <= off0)
		return -1;
	
	/*
	 * Adjust buffer start for the offset.
	 */
	nb->len -= off0;
	nb->data += off0;
	for (;n0 && len; n0 = n0->nextBuf) {
		if (n0->len <= 0)
			continue;
		w = nBUFTOPTR(n0, u_short *);
		if (bufLen == -1) {
			/*
			 * The first byte of this nBuf is the continuation
			 * of a word spanning between this nBuf and the
			 * last nBuf.
			 *
			 * s_util.c[0] is already saved when scanning previous 
			 * nBuf.
			 */
			s_util.c[1] = *(char *)w;
			sum += s_util.s;
			w = (u_short *)((char *)w + 1);
			bufLen = n0->len - 1;
			len--;
		} else
			bufLen = n0->len;
		if (len < bufLen)
			bufLen = len;
		len -= bufLen;
		/*
		 * Force to even boundary.
		 */
		if ((1 & (int) w) && (bufLen > 0)) {
			REDUCE;
			sum <<= 8;
			s_util.c[0] = *(u_char *)w;
			w = (u_short *)((char *)w + 1);
			bufLen--;
			byte_swapped = 1;
		}
		/*
		 * Unroll the loop to make overhead from
		 * branches &c small.
		 */
		while ((bufLen -= 32) >= 0) {
			sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
			sum += w[4]; sum += w[5]; sum += w[6]; sum += w[7];
			sum += w[8]; sum += w[9]; sum += w[10]; sum += w[11];
			sum += w[12]; sum += w[13]; sum += w[14]; sum += w[15];
			w += 16;
		}
		bufLen += 32;
		while ((bufLen -= 8) >= 0) {
			sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
			w += 4;
		}
		bufLen += 8;
		if (bufLen == 0 && byte_swapped == 0)
			continue;
		REDUCE;
		while ((bufLen -= 2) >= 0) {
			sum += *w++;
		}
		if (byte_swapped) {
			REDUCE;
			sum <<= 8;
			byte_swapped = 0;
			if (bufLen == -1) {
				s_util.c[1] = *(char *)w;
				sum += s_util.s;
				bufLen = 0;
			} else
				bufLen = -1;
		} else if (bufLen == -1)
			s_util.c[0] = *(char *)w;
	}
	/*
	 * Reset buffer start for the offset.
	 */
	nb->len += off0;
	nb->data -= off0;
	
	if (len)
		IPDEBUG((LOG_ERR, TL_IP, "inChkSum: out of data"));
	if (bufLen == -1) {
		/* The last nBuf has odd # of bytes. Follow the
		   standard (the odd byte may be shifted left by 8 bits
		   or not as determined by endian-ness of the machine) */
		s_util.c[1] = 0;
		sum += s_util.s;
	}
	REDUCE;
	return ((u_short)(~sum) & 0xffff);
}


/**********************************/
/*** LOCAL FUNCTION DEFINITIONS ***/
/**********************************/

