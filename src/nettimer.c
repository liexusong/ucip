/*****************************************************************************
* timer.c - Timer Services program file.
*
* Copyright (c) 1998 by Global Election Systems Inc.
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
* 98-01-23 Guy Lancaster <lancasterg@acm.org>, Global Election Systems Inc.
*	Original.
*****************************************************************************/

#include "netconf.h"
#include "net.h"
#include "netbuf.h"
#include "nettimer.h"

#include <stdio.h>
#include "netdebug.h"


/*************************/
/*** LOCAL DEFINITIONS ***/
/*************************/
#define TIMER_STACK_SIZE	NETSTACK	/* Timers are used for network protocols. */
#define MAXFREETIMERS 4					/* Number of free timers allocated. */

                                                                    
/***********************************/
/*** LOCAL FUNCTION DECLARATIONS ***/
/***********************************/
static void nullTimer(void *);
static void timerTask(void *data);


/*****************************/
/*** LOCAL DATA STRUCTURES ***/
/*****************************/
#ifdef OS_DEPENDENT
static OS_EVENT *mutex;
#endif

static char timerStack[TIMER_STACK_SIZE];
static Timer timerHead;					/* Sentinal for timer queue. */
static Timer *timerFree;				/* The free list pointer. */
static Timer timerHeap[MAXFREETIMERS];	/* The free timer records. */


/***********************************/
/*** PUBLIC FUNCTION DEFINITIONS ***/
/***********************************/
/*
 * timerInit - Initialize the timer timer subsystem.
 */
void timerInit(void)
{
	int i;
	
	/* Initialize the timer queue sentinal. */
	memset(&timerHead, 0, sizeof(Timer));
	timerHead.timerNext = &timerHead;
	timerHead.timerPrev = &timerHead;
	timerHead.expiryTime = OSTimeGet() + MAXJIFFYDELAY;
	timerHead.timerHandler = nullTimer;
	
	/* Initialize the timer free list. */
	timerFree = &timerHeap[0];
	memset(timerFree, 0, sizeof(timerHeap));
	for (i = 0; i < MAXFREETIMERS; i++) {
		timerHeap[i].timerFlags = TIMERFLAG_TEMP;
		timerHeap[i].timerNext = &timerHeap[i + 1];
	}
	timerHeap[MAXFREETIMERS - 1].timerNext = NULL;
	
	/* Start the timer task. */
#ifdef OS_DEPENDENT
	mutex = OSSemCreate(1);
	OSTaskCreate(timerTask, NULL, timerStack+TIMER_STACK_SIZE, PRI_TIMER);
#endif
}


/*
 * timeoutJiffy - Set a timer for a timeout in Jiffy time.  
 * A Jiffy is a system clock tick.  The timer will time out at the
 * specified system time.
 * RETURNS: Zero if OK, otherwise an error code.
 */
INT timeoutJiffy
(
	Timer *timerHdr,				/* Pointer to timer record. */
	ULONG timeout,					/* The timeout in Jiffy time. */
	void (* timerHandler)(void *),	/* The timer handler function. */
	void *timerArg					/* Arg passed to handler. */
)
{
	Timer *nextTimer;
	INT st = 0;
	
	/* Validate parameters. */
	if (!timerHdr || !timerHandler)
		st = -1;
	else {
#ifdef OS_DEPENDENT
		OSSemPend(mutex, 0);
#endif
		
		/* Check that the timer is not active already. */
		if (timerHdr->timerPrev != NULL) {
			(timerHdr->timerNext)->timerPrev = timerHdr->timerPrev;
			(timerHdr->timerPrev)->timerNext = timerHdr->timerNext;
		}
		
		/* Load the timer record. */
	    timerHdr->expiryTime = timeout;
	    timerHdr->timerHandler = timerHandler;
	    timerHdr->timerArg = timerArg;
	    
	    /* Insert the record in the timer queue. */
		for (nextTimer = timerHead.timerNext;
			nextTimer != &timerHead 
				&& (long)(timerHdr->expiryTime - nextTimer->expiryTime) > 0;
			nextTimer = nextTimer->timerNext
		);
		timerHdr->timerNext = nextTimer;
		(timerHdr->timerPrev = nextTimer->timerPrev)->timerNext = timerHdr;
		nextTimer->timerPrev = timerHdr;
		
#ifdef OS_DEPENDENT
		OSSemPost(mutex);
#endif
	}
	return st;
}



/*
 * timerJiffys - Set a timer in Jiffys.  A Jiffy is a system clock
 * tick.  A delay of zero will invoke the timer handler on the next 
 * Jiffy interrupt.
 * RETURNS: Zero if OK, otherwise an error code.
 */
INT timerJiffys
(
	Timer *timerHdr,				/* Pointer to timer record. */
	ULONG timerDelay,				/* The delay value in Jiffys. */
	void (* timerHandler)(void *),	/* The timer handler function. */
	void *timerArg					/* Arg passed to handler. */
)
{
	INT st = 0;
	
	/* Validate parameters. */
	if (timerDelay > MAXJIFFYDELAY)
		st = -1;
	else 
		st = timeoutJiffy(timerHdr, timerDelay + OSTimeGet(), timerHandler, timerArg);
		
	return st;
}


/*
 * timerSeconds - Set a timer in seconds.  A delay of zero will
 * invoke the timer handler on the next Jiffy interrupt.
 * RETURNS: Zero if OK, otherwise an error code.
 */
INT timerSeconds
(
	Timer *timerHdr,				/* Pointer to timer record. */
	ULONG timerDelay,				/* The delay value in seconds. */
	void (* timerHandler)(void *),	/* The timer handler function. */
	void *timerArg					/* Arg passed to handler. */
)
{
    return timeoutJiffy(
    			timerHdr, 
    			OSTimeGet() + timerDelay * TICKSPERSEC, 
    			timerHandler, 
    			timerArg);
}


/*
 * timerTempSeconds - Get a temporary timer from the free list and set
 * it in seconds.  Note that you don't get a handle on the timer record.
 * The record will be automatically returned to the free list when either
 * it expires or it is cancelled.
 *  RETURNS: Zero if OK, otherwise an error code.
 */
INT timerTempSeconds
(
	ULONG timerDelay,				/* The delay value in seconds. */
	void (* timerHandler)(void *),	/* The timer handler function. */
	void *timerArg					/* Arg passed to handler. */
)
{
	INT st;
	
#ifdef OS_DEPENDENT
	OSSemPend(mutex, 0);
#endif
	if (timerFree == NULL) {
#ifdef OS_DEPENDENT
		OSSemPost(mutex);
#endif
		TIMERDEBUG((LOG_ERR, "timerTempSeconds: No free timer"));
		st = -1;					/* XXX An allocation error code? */
	}
	else {
		Timer *curTimer = timerFree;
		
		timerFree = timerFree->timerNext;
#ifdef OS_DEPENDENT
		OSSemPost(mutex);
#endif
		
		st = timerJiffys(curTimer, timerDelay * TICKSPERSEC, timerHandler, timerArg);
	}
	return st;
}


/*
 * timerClear() - Clear the given timer.
 */
void timerClear
(
	Timer *timerHdr					/* Pointer to timer record. */
)
{
	/* 
	 * Since the queue is circular, a null prev link means the timer is not
	 * on the queue (the free list only uses next).  Otherwise we extract it
	 * and if it's a temporary timer, put it back on the free list.
	 */
#ifdef OS_DEPENDENT
	OSSemPend(mutex, 0);
#endif
	if (timerHdr->timerPrev) {
		(timerHdr->timerNext)->timerPrev = timerHdr->timerPrev;
		(timerHdr->timerPrev)->timerNext = timerHdr->timerNext;
		timerHdr->timerPrev = NULL;
		
		if (timerHdr->timerFlags & TIMERFLAG_TEMP) {
			timerHdr->timerNext = timerFree;
			timerFree = timerHdr;
		}
	}
#ifdef OS_DEPENDENT
	OSSemPost(mutex);
#endif
}

/*
 *	timerCancel - Clear the first matching timer for the given function
 *	pointer and argument.
 */
void timerCancel(
	void (* timerHandler)(void *),	/* The timer handler function. */
	void *timerArg					/* Arg passed to handler. */
)
{
	Timer *curTimer;
	
#ifdef OS_DEPENDENT
	OSSemPend(mutex, 0);
#endif
	for (curTimer = timerHead.timerNext;
		curTimer != &timerHead 
			&& (curTimer->timerHandler != timerHandler
				|| curTimer->timerArg != timerArg);
		curTimer = curTimer->timerNext
	);
	if (curTimer != &timerHead) {
		(curTimer->timerNext)->timerPrev = curTimer->timerPrev;
		(curTimer->timerPrev)->timerNext = curTimer->timerNext;
		curTimer->timerPrev = NULL;
		
		if (curTimer->timerFlags & TIMERFLAG_TEMP) {
			curTimer->timerNext = timerFree;
			timerFree = curTimer;
		}
	}
#ifdef OS_DEPENDENT
	OSSemPost(mutex);
#endif
}


/*
 * timerCheck - If there are any expired timers, wake up the timer task.
 * This is designed to be called from within the Jiffy timer interrupt so
 * it has to have minimal overhead.
 */
void timerCheck(void)
{
#ifdef OS_DEPENDENT
	if ((long)(timerHead.timerNext->expiryTime - OSTimeGet()) <= 0)
		(void) OSTaskResume(PRI_TIMER);
#endif
}


/**********************************/
/*** LOCAL FUNCTION DEFINITIONS ***/
/**********************************/
/*
 * nullTimer - Do nothing.  Used as the timer handler for the sentinal record.
 * This means that the timer interrupt handler doesn't need to do a separate 
 * test for the timer queue being empty.
 */
#pragma argsused
static void nullTimer(void *x)
{
}

/*
 * The timer handler task.  This is used to service timer handlers that take
 * non-trivial time.
 */
#pragma argsused
static void timerTask(void *data)
{	
	Timer *thisTimer;
	void (* timerHandler)(void *);
	void *timerArg;

	for (;;) {
		/* If no ready timers, wait for one.  Note that the mutex is just
		 * to protect the timer queue.  Somebody needs to wake us up when
		 * a timer expires. */
#ifdef OS_DEPENDENT
		OSSemPend(mutex, 0);
#endif
		thisTimer = timerHead.timerNext;
		if ((long)(thisTimer->expiryTime - OSTimeGet()) > 0) {
#ifdef OS_DEPENDENT
			OSSemPost(mutex);
			(void) OSTaskSuspend(OS_PRIO_SELF);
#endif
		}
		else {
			/* If the timer is the sentinal, reset the expiry time to the
			 * maximum delay.  This way the timer interrupt handler doesn't
			 * need to do a separate test for the timer queue being empty.
			 */
			if (thisTimer == &timerHead) {
				timerHead.expiryTime = OSTimeGet() + MAXJIFFYDELAY;
			}
			else {
				/* Remove the timer from the queue and if it's marked
				 * as temporary, put it back on the free list. */
				thisTimer = timerHead.timerNext;
				(timerHead.timerNext = thisTimer->timerNext)->timerPrev = &timerHead;
				thisTimer->timerPrev = NULL;
				if (thisTimer->timerFlags & TIMERFLAG_TEMP) {
					thisTimer->timerNext = timerFree;
					timerFree = thisTimer;
				}
			}
			
			/* Update timer counter - used as activity counter for
			 * development purposes. */
			thisTimer->timerCount++;
			
			/* Get the handler parameters which could change when
			 * we post the mutex. */
			timerHandler = thisTimer->timerHandler;
			timerArg = thisTimer->timerArg;
			
			/* Invoke the timer handler.  Make sure that we post the mutex 
			 * first so that we don't deadlock if the handler tries to reset
			 * the timer. */
#ifdef OS_DEPENDENT
			OSSemPost(mutex);
#endif
			timerHandler(timerArg);
		}
	}
}

