/*****************************************************************************
* debug.h - System debugging utilities.
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
* 98-07-29 Guy Lancaster <lancasterg@acm.org>, Global Election Systems Inc.
*	Original.
*****************************************************************************/

#ifndef DEBUG_H
#define DEBUG_H


/************************
*** PUBLIC DATA TYPES ***
************************/
/* Trace levels. */
typedef enum {
	LOG_CRITICAL = 0,
	LOG_ERR = 1,
	LOG_NOTICE = 2,
	LOG_WARNING = 3,
	LOG_INFO = 5,
	LOG_DETAIL = 6,
	LOG_DEBUG = 7
} LogCodes;


/* 
 * Trace module codes - used as indices into the traceLev array of trace 
 * levels. 
 * *** NOTE: There must be an entry in the maskModuleToken in debug.c for
 * *** each entry here.
 */
typedef enum {
	TL_UNDEF,					/* Undefined module. */
	TL_PPP,						/* PPP */
	TL_IP,						/* IP */
	TL_TCP,						/* TCP */
	TL_CHAT,					/* Modem dialer */
	TL_ECHO,					/* TCP echo service. */
	TL_FEEDER,					/* Accu-Feed */
	TL_SCAN,					/* Scanner control. */
	TL_MAX						/*** Max modules - leave at end ***/
} TraceModule;

#define LOGMSGLEN 80					/* Max length of a log message. */


/*****************************
*** PUBLIC DATA STRUCTURES ***
*****************************/
extern INT debug;


/***********************
*** PUBLIC FUNCTIONS ***
***********************/
extern char *debugchr(char *d, unsigned char c);

void debugInit(void);
void monStart(void);
void setTraceLevel(INT level, TraceModule tMod);
int getTraceLevel(TraceModule tMod);


/*
 *	trace - a form of printf to send tracing information to stderr
 */
void trace(int level, const char FAR *format,...);

/*
 * logTrace - A form of printf that writes a line to the trace log if
 *	the trace level for the specified module is high enough.
 */
void logTrace(int level, TraceModule tMod,  const char FAR *format,...);

/*
 * Print the given lines from the trace log in readable form to the
 *	specified file stream.  The previous start and max lines are saved so
 *	that if they are passed as -1, the dump displays the next set of lines.
 */
void traceDump(FILE *fptr, int startLine, int maxLines);

#endif


