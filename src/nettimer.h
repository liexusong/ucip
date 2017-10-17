/*****************************************************************************
* timer.h - Timer Services header file.
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
* THEORY OF OPERATION
*
*   The timer subsystem is used for invoking functions after a specified delay.
* When a timer expires, the timer handling function is invoked with the
* arguement specified when the timer was set.
*
*	Timer records (referred to as "timers") are allocated by the calling
* function either statically or dynamically.  The record should be filled
* with null bytes before first being set.  Timers may be reset or cancelled
* before expiry.
*
******************************************************************************
* REVISION HISTORY
*
* 98-01-23 Guy Lancaster <glanca@gesn.com>, Global Election Systems Inc.
*	Original.
*****************************************************************************/

#ifndef TIMER_H
#define TIMER_H


/*************************
*** PUBLIC DEFINITIONS ***
*************************/
/* The maximum time delays.  The maximum useful delay is half of ULONG_MAX
 * because after this we wrap when compared with diffTime(). */
#define MAXJIFFYDELAY (ULONG_MAX/2)
#define MAXMILLIDELAY ULONG_MAX

/* Timer flags. */
#define TIMERFLAG_TEMP 1			/* Timer is temporary. */


/************************
*** PUBLIC DATA TYPES ***
************************/
/* Timer record headers. */
typedef struct Timer_s
{
	struct Timer_s *timerNext;		/* Next timer in queue. */
	struct Timer_s *timerPrev;		/* Previous timer in queue. */
	u_short timerFlags;				/* Timer control flags. */
	ULONG expiryTime;				/* Expiry time in Jiffys. */
	void (* timerHandler)(void *);	/* Ptr to the timer handler function. */
	void *timerArg;					/* Argument passed to timer handler. */
	INT  timerCount;				/* Diagnostic usage count. */
} Timer;


/***********************
*** PUBLIC FUNCTIONS ***
***********************/
/*
 * timerInit - Initialize the timer timer subsystem.
 */
void timerInit(void);


/*
 * timerCreate - Initialize a timer record.  MUST be called before
 * setting that timer record.  MUST NOT be called on an active timer.
 */
#define timerCreate(t) memset((t), 0, sizeof(Timer))


/*
 * timerDelete - Clear a timer record.  MUST be called before the
 * memory for a timer record is altered by any non-timer function.
 * MUST NOT be called before the timer record has been created.
 */
#define timerDelete(t) timerClear(t)


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
);


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
);

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
);


/*
 * timerTempSeconds - Get a temporary timer from the free list and set
 * it in seconds.  Note that you don't get a handle on the timer record.
 *  RETURNS: Zero if OK, otherwise an error code.
 */
INT timerTempSeconds
(
	ULONG timerDelay,				/* The delay value in seconds. */
	void (* timerHandler)(void *),	/* The timer handler function. */
	void *timerArg					/* Arg passed to handler. */
);


/*
 * timerClear() - Clear the given timer.
 */
void timerClear
(
	Timer *timerHdr					/* Pointer to timer record. */
);


/*
 *	timerCancel - Clear the first matching timer for the given function
 *	pointer and argument.
 */
void timerCancel(
	void (* timerHandler)(void *),	/* The timer handler function. */
	void *timerArg					/* Arg passed to handler. */
);

/*
 *	TIMEOUT and UNTIMEOUT support the BSD code timeouts.
 */
#define TIMEOUT(f, a, t)	timerTempSeconds((t), (f), (a))
#define UNTIMEOUT(f, a)		timerCancel((f), (a))

/*
 * timerCheck - If there are any expired timers, wake up the timer task.
 * This is designed to be called from within the Jiffy timer interrupt so
 * it has to have minimal overhead.
 */
void timerCheck(void);

#endif
