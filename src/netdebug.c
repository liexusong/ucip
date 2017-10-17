/*****************************************************************************
* debug.c - Developer debugging utilities - not used in release versions.
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
* 98-07-29 Guy Lancaster <lancasterg@acm.org>, Global Election Systems Inc.
*	Original.
*****************************************************************************/

#include "netconf.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include "netbuf.h"
#include "net.h"
#include "netppp.h"
#include "netip.h"
#include "nettcp.h"

#include "netdebug.h"

#define DEBUGMONPORT 0					/* Set > 0 for diag mon on modem port. */


/***************************/
/*** PRIVATE DEFINITIONS ***/
/***************************/
#define TCPPORT_ACCUVOTE 3031			/* Monitor port number. */
#define MAXLOGSZ 128					/* Number of messages in debug log. */
#define MAXSENDLINES 20					/* Number of trace lines to send. */
#define CMDLINESZ 200					/* Max length of a command line. */
#define MAXCMDARGS 5					/* Max arguements on a command. */
#define SENDLINESZ LOGMSGLEN+50			/* Max length of a line to send. */
#define NUM_MON 1						/* Number of monitor sessions. */
#define STACK_SIZE OSMINSTACK+800		/* Monitor stack size. */
#define TOKENLEN 20						/* Max length of a token string. */
#define MONPROMPT "> "					/* The monitor prompt string. */
#define MONPROMPTLEN 2					/* Length of the monitor prompt. */
#define TERMWIDTH 80					/* Length of a terminal line. */
#define MONTCP_KEEPALIVE 60				/* Keep alive probe delay in seconds. */

/*
 * WARNING: Make sure that there is an entry in the cmdFcn table for each 
 *	entry here.
 * Note: The SENDSTR command is not actually a user command but is used
 *	to display syntax and error messages if command parsing fails.
 */
typedef enum {
	MONCMD_SENDSTR = 0,					/* Send the send string. */
	MONCMD_DUMP,						/* Display a page of a trace or log. */
	MONCMD_SET,							/* Set parameters. */
	MONCMD_DISPLAY						/* Display tables. */
} MonitorCommands;

typedef enum {
	MONDUMP_TRACE = 0,					/* Set the trace levels. */
	MONDUMP_SCAN						/* Display raw scan data. */
} DumpOptions;

typedef enum {
	MONSET_TRACE = 0					/* Set the trace levels. */
} SetCommandOptions;

typedef enum {
	MONDISP_MCARD = 0,					/* Display memory card status. */
	MONDISP_BUFFER,						/* Display the buffer statistics. */
	MONDISP_TCP,						/* Display TCP session statistics. */
	MONDISP_IP,							/* Display IP statistics. */
	MONDISP_PPP,						/* Display PPP session statistics. */
	MONDISP_SERIAL						/* Display serial driver statistics. */
} DisplayOptions;

#define MONCMDLIST "\t\tAccu-Vote Monitor Commands\r\n\
\t    DUMP - display a page information\r\n\
\t DISPLAY - display a table\r\n\
\t     SET - set parameters\r\n"

#define MONDUMPOPTIONS "\t\tAccu-Vote Monitor Dump Options\r\n\
\t  TRACE <start> <lines> - Display trace lines from start to end\r\n\
\t  SCAN <start> <lines>  - Display raw scan data lines from start to end\r\n"

#define MONSETOPTIONS "\t\tAccu-Vote Monitor Set Options\r\n\
\t  TRACE <module> <level> - set a module's trace level\r\n"

#define MONDISPOPTIONS "\t\tAccu-Vote Monitor Display Options\r\n\
\t  MEMCARD - Display the memory card status\r\n\
\t  BUFFERS - Display network buffer statistics\r\n\
\t  TCP     - Display TCP session statistics\r\n\
\t  IP      - Display IP statistics\r\n\
\t  PPP     - Display PPP session statistics\r\n\
\t  SERIAL  - Display serial I/O statistics\r\n"

#define TRACEMASKOPTIONS "\t\tAccu-Vote Monitor Trace Mask Options (when enabled)\r\n\
\tUNDEF - Set trace mask for undefined modules\r\n\
\tPPP   - Set trace mask for PPP driver\r\n\
\tIP    - Set trace mask for IP router\r\n\
\tTCP   - Set trace mask for TCP operations\r\n\
\tCHAT  - Set trace mask for CHAT modem dialer\r\n\
\tECHO   - Set trace level for ECHO service\r\n\
\tFEEDER - Set trace level for Accu-Feed control\r\n\
\tSCAN   - Set trace level for Accu-Vote's scanner\r\n"

#define TRACELEVELOPTIONS "\t\tAccu-Vote Monitor Trace Mask Values\r\n\
\tERR,1     - Log critical errors\r\n\
\tNOTICE,2  - Log non-critical errors\r\n\
\tWARNING,3 - Log warnings\r\n\
\tINFO,5    - Log informative messages\r\n\
\tDETAIL,6  - Log detail messages\r\n\
\tDEBUG,7   - Log debugging trace messages\r\n"

#define DUMPSTARTVALUES "\t\tAccu-Vote Monitor Dump Start Values\r\n\
\t<Start>	- Optional number to start the dump at\r\n"

#define DUMPLINESVALUES "\t\tAccu-Vote Monitor Dump Lines Values\r\n\
\t<Lines>	- Optional number of lines to dump (default 20)\r\n"


/**************************/
/*** PRIVATE DATA TYPES ***/
/**************************/
struct MonitorControl_s;
struct TokenTable_s;
typedef int ParseFcn(struct MonitorControl_s *mc, const char *tokenPtr, int tokenLen);
typedef int CmdFcn(struct MonitorControl_s *mc);

/*
 * Monitor control block.
 */
typedef struct MonitorControl_s {
	FILE *fp;									/* File device pointer. */
	char cmdBuf[CMDLINESZ + 1];					/* Current command line. */
	int cmdLen;									/* Current length of command. */
	ParseFcn *parseFcn;							/* Current parsing function. */
	CmdFcn *commandFcn;							/* Current monitor command. */
	int curCmdArgs[MAXCMDARGS];					/* Arguments for the current command. */
	int curCmdArgQty;							/* Number of arguements for command. */
	const struct TokenTable_s *curTokenTbl;		/* Current token table. */
	char *sendStr;								/* String to be sent. */
	char monitorStack[STACK_SIZE];				/* The monitor task stack. */
} MonitorControl;

/*
 * Token table structure used for parsing.
 */
typedef struct TokenTable_s {
	char *tokenLabel;							// Token literal.
	int  tokenValue;							// Value for this token.
	ParseFcn *parseFcn;							/* Current parsing function. */
	const struct TokenTable_s *nextTbl;			// Table for next token.
	char *errStr;								// Error string if next token fails.
} TokenTable;

typedef struct DebugLog_t {
	ULONG logTime;								/* Time of message. */
    UINT  OSTCBPrio;							/* Current Task priority */
	ULONG arg1, arg2;							/* Numeric trace arguements */
	char logMsg[LOGMSGLEN + 1];					/* Trace message. */
} DebugLog;


/***********************************/
/*** LOCAL FUNCTION DECLARATIONS ***/
/***********************************/
#if DEBUG_SUPPORT > 0
static void monitorMain0(void *arg);
#if DEBUGMONPORT > 0
static void monitorMain1(void *arg);
#endif
static int monProcInput(MonitorControl *mc, char *rBuf, int inCnt);
static int monParseCmd(MonitorControl *mc);
static int parseCmdToken(MonitorControl *mc, const char *tokenPtr, int tokenLen);
static int parseCmdArg(MonitorControl *mc, const char *tokenPtr, int tokenLen);
static int parseEOL(MonitorControl *mc, const char *tokenPtr, int tokenLen);
static int monDump(MonitorControl *mc);
static int monSendStr(MonitorControl *mc);
static int monSet(MonitorControl *mc);
static int monDisplay(MonitorControl *mc);
static int monSendMask(MonitorControl *mc);
static int monSendStats(MonitorControl *mc, DiagStat ds[]);
static const TokenTable *findToken(const char *tokenPtr, int tokenLen, const TokenTable *tt);
#endif

/*******************************/
/*** PRIVATE DATA STRUCTURES ***/
/*******************************/
#if DEBUG_SUPPORT > 0

DebugLog debugLog[MAXLOGSZ];			/* Debug trace log. */
u_int logTail = 0, logHead = 0;			/* Indexes to top and bottom of log. */
MonitorControl monitorControl[2];		/* The monitor control blocks. */

/*
 * The command execution function vectors.
 */
CmdFcn * const cmdFcn[] = {
	monSendStr,				/* MONCMD_SENDSTR - Used for error messages. */
	monDump,				/* MONCMD_DUMP */
	monSet,					/* MONCMD_SET */
	monDisplay				/* MONCMD_DISPLAY */
};

/*
 * Set mask command module option lookup table.
 */
const TokenTable traceLevelToken[] = {
	{"ERROR",	LOG_ERR,		parseEOL,	NULL},
	{"NOTICE",	LOG_NOTICE,		parseEOL,	NULL},
	{"WARNING",	LOG_WARNING,	parseEOL,	NULL},
	{"INFO",	LOG_INFO,		parseEOL,	NULL},
	{"DETAIL",	LOG_DETAIL,		parseEOL,	NULL},
	{"DEBUG",	LOG_DEBUG,		parseEOL,	NULL},
	{"%d",		0,				parseEOL,	NULL},
	{"", 0}
};

/*
 * Set mask command module option lookup table.
 */
const TokenTable maskModuleToken[] = {
	{"UNDEF",	TL_UNDEF,		parseCmdArg,	traceLevelToken, TRACELEVELOPTIONS},
	{"PPP",		TL_PPP,			parseCmdArg,	traceLevelToken, TRACELEVELOPTIONS},
	{"IP",		TL_IP,			parseCmdArg,	traceLevelToken, TRACELEVELOPTIONS},
	{"TCP",		TL_TCP,			parseCmdArg,	traceLevelToken, TRACELEVELOPTIONS},
	{"CHAT",	TL_CHAT,		parseCmdArg,	traceLevelToken, TRACELEVELOPTIONS},
	{"ECHO",	TL_ECHO,		parseCmdArg,	traceLevelToken, TRACELEVELOPTIONS},
#if TRACEFEEDER > 0
	{"FEEDER",	TL_FEEDER,		parseCmdArg,	traceLevelToken, TRACELEVELOPTIONS},
#endif
#if TRACESCAN > 0
	{"SCAN",	TL_SCAN,		parseCmdArg,	traceLevelToken, TRACELEVELOPTIONS},
#endif
	{"", 0}
};

const TokenTable dumpLinesToken[] = {
	{"%d",		0,				parseEOL,	NULL,			NULL},
	{"", 0}
};

const TokenTable dumpStartToken[] = {
	{"%d",		0,				parseCmdArg,	dumpLinesToken,	DUMPLINESVALUES},
	{"", 0}
};

/*
 * Dump command option lookup table.
 */
const TokenTable dumpOptToken[] = {
	{"TRACE",	MONDUMP_TRACE,	parseCmdArg,	dumpStartToken,	DUMPSTARTVALUES},
	{"SCAN",	MONDUMP_SCAN,	parseCmdArg,	dumpStartToken,	DUMPSTARTVALUES},
	{"", 0}
};

/*
 * Set command option lookup table.
 */
const TokenTable setOptToken[] = {
	{"TRACE",	MONSET_TRACE,	parseCmdArg,	maskModuleToken, TRACEMASKOPTIONS},
	{"", 0}
};

/*
 * Display command option lookup table.
 */
const TokenTable displayOptToken[] = {
	{"MEMCARD",	MONDISP_MCARD,	parseEOL,	NULL},
	{"BUFFERS",	MONDISP_BUFFER,	parseEOL,	NULL},
	{"TCP",		MONDISP_TCP,	parseEOL,	NULL},
	{"IP",		MONDISP_IP,		parseEOL,	NULL},
	{"PPP",		MONDISP_PPP,	parseEOL,	NULL},
	{"SERIAL",	MONDISP_SERIAL,	parseEOL,	NULL},
	{"", 0}
};

/* 
 * Command token lookup table.  Note that the order is important since we'll
 * match on the first string that matches the user's entered characters.
 */
const TokenTable cmdToken[] = {
	{"DUMP",	MONCMD_DUMP,	parseCmdArg,	dumpOptToken,		MONDUMPOPTIONS},
	{"SET",		MONCMD_SET,		parseCmdArg,	setOptToken,		MONSETOPTIONS},
	{"DISPLAY",	MONCMD_DISPLAY,	parseCmdArg,	displayOptToken,	MONDISPOPTIONS},
	{"\r\n",	MONCMD_DUMP,	parseCmdArg,	dumpOptToken,		MONDUMPOPTIONS},
	{"", 0}
};



#endif


/******************************/
/*** PUBLIC DATA STRUCTURES ***/
/******************************/
#if DEBUG_SUPPORT > 0

int traceLevel[TL_MAX];					/* Module trace levels. */

#endif


/************************/
/*** PUBLIC FUNCTIONS ***/
/************************/
void debugInit(void)
{
#if DEBUG_SUPPORT > 0
	int i;
	
	memset(debugLog, 0, sizeof(debugLog));
	for (i = 0; i < TL_MAX; i++)
		traceLevel[i] = LOG_INFO;
#endif
}

void monStart(void)
{
#if DEBUG_SUPPORT > 0
	/* Start the monitor tasks. */
	OSTaskCreate(monitorMain0, (void *)0, 
			monitorControl[0].monitorStack + STACK_SIZE, PRI_MON0);
#if DEBUGMONPORT > 0
	/* Start the monitor tasks. */
	OSTaskCreate(monitorMain1, (void *)1, 
			monitorControl[1].monitorStack + STACK_SIZE, PRI_MON1);
#endif
#endif
}

#pragma argsused
void setTraceLevel(INT level, TraceModule tMod)
{
#if DEBUG_SUPPORT > 0
	traceLevel[tMod] = level;
#endif
}

#pragma argsused
int getTraceLevel(TraceModule tMod)
{
#if DEBUG_SUPPORT > 0
	return traceLevel[tMod];
#else
	return 0;
#endif
}


/*	trace - a form of printf to write a line to the trace log.
 */
#pragma argsused
void trace(int level, const char *format,...) 
{
#if DEBUG_SUPPORT > 0
	char **arg = (char **)&format;				/* ptr to arg list on stack */
	int  logNdx;
	
	if (level <= traceLevel[TL_UNDEF]) {
		OS_ENTER_CRITICAL();
		logNdx = logHead++ % MAXLOGSZ;
		/* If the log is full, drop the oldest entry. */
		if (logHead % MAXLOGSZ == logTail % MAXLOGSZ)
			logTail++;
		OS_EXIT_CRITICAL();
		
		/* Note: mtime() exits with interrupts enabled. */
		debugLog[logNdx].logTime = mtime();
		
		debugLog[logNdx].OSTCBPrio = OSTCBCur->OSTCBPrio + 100;
		arg++;							/* Point to first arguement if any */
		if (vsprintf(debugLog[logNdx].logMsg, format, (const void *)arg) >= LOGMSGLEN)
			panic("TRACE");
	}
#endif
}


/*
 * logTrace - A form of printf that writes a line to the trace log if
 *	the trace level for the specified module is high enough.
 */
#pragma argsused
void logTrace(int level, TraceModule tMod,  const char FAR *format,...)
{
#if DEBUG_SUPPORT > 0
	char **arg = (char **)&format;				/* ptr to arg list on stack */
	u_int  logNdx;
	
	if (level <= traceLevel[tMod]) {
		OS_ENTER_CRITICAL();
		logNdx = logHead++ % MAXLOGSZ;
		/* If the log is full, drop the oldest entry. */
		if (logHead % MAXLOGSZ == logTail % MAXLOGSZ)
			logTail++;
		OS_EXIT_CRITICAL();
		
		/* Note: mtime() exits with interrupts enabled. */
		debugLog[logNdx].logTime = mtime();
		
		debugLog[logNdx].OSTCBPrio = OSTCBCur->OSTCBPrio + 100;
		arg++;							/* Point to first arguement if any */
		if (vsprintf(debugLog[logNdx].logMsg, format, (const void *)arg) >= LOGMSGLEN)
			panic("LOGTRACE");
	}
#endif
}


/*  Generate the a string in d containing the character c if printable,
 *  otherwise a bracketed mnemonic for it.  Return d.
 */
#pragma argsused
char *debugchr(char *d, unsigned char c)
{
#if DEBUG_SUPPORT > 0
	INT  fndx;
	char fstr[12], *dptr = d;

	switch (c) {
	case (NUL): 
		strcpy(d, "<NUL>"); 
		break;
	case (ACK): 
		strcpy(d, "<ACK>"); 
		break;
	case (NAK): 
		strcpy(d, "<NAK>"); 
		break;
	case (LF):  
		strcpy(d, "<LF>"); 
		break;
	case (FF):  
		strcpy(d, "<FF>"); 
		break;
	case (CR):  
		strcpy(d, "<CR>"); 
		break;
	case (RTS): 
		strcpy(d, "<RTS>"); 
		break;
	case (EOD): 
		strcpy(d, "<EOD>"); 
		break;
	case (EOF): 
		strcpy(d, "<EOF>"); 
		break;
	default:
		if (c < 32 || c >= 127) {
			fndx = 0;
			*dptr++ = '<';
			/* Convert number */
			if (c == 0) {
				fstr[fndx++] = '0';
			} else {
				while (c > 0 && fndx < 10) {
					fstr[fndx++] = (c % 10) + '0';
					c = c / 10;
				}
			}
			for (fndx--; fndx >= 0; fndx--) {
				*dptr++ = fstr[fndx];
			}
			*dptr++ = '>';
		} else
			*dptr++ = c;
		*dptr = '\0';
		break;
	}
	return(d);
#endif
}

/*
 * Print the given lines from the trace log in readable form to the
 *	specified file stream.  The previous start and max lines are saved so
 *	that if they are passed as -1, the dump displays the next set of lines.
 */
#pragma argsused
void traceDump(FILE *fptr, int startLine, int maxLines)
{
#if DEBUG_SUPPORT > 0
	int rc;
	static UINT curLine = 0;
	static int curMax = MAXSENDLINES;
	UINT endLine, logNdx;
	
	// Load parameters
	if (startLine >= 0)
		curLine = startLine;
	if (maxLines > 0)
		curMax = maxLines;
	if (curLine < logTail)
		curLine = logTail;
	else if (curLine > logHead)
		curLine = logHead;
	endLine = curLine + curMax;
	if (endLine > logHead)
		endLine = logHead;
		
	for (; curLine < endLine; curLine++) {
		logNdx = curLine % MAXLOGSZ; 
		
		rc = fprintf(fptr, "%4u>%9lu: %.*s\r\n", 
				curLine,
				debugLog[logNdx].logTime,
				LOGMSGLEN,
				debugLog[logNdx].logMsg);
		/* 
		 * If we wrote more characters than fit on a terminal line, count it
		 * as 2 lines.  We don't count the leading CR/LF.
		 */
		if (rc > TERMWIDTH + 2)
			endLine--;
	}
	fflush(fptr);
#endif
}


/**********************************/
/*** LOCAL FUNCTION DEFINITIONS ***/
/**********************************/
/*
 * monitorMain0 - an interactive diagnostics monitor designed to be run as a
 * task connected via a telnet connection.
 */
#if DEBUG_SUPPORT > 0
static void monitorMain0(void *md)
{
	MonitorControl *mc = &monitorControl[(int)md];
	#define READBUFSZ 50
	struct sockaddr_in localAddr, peerAddr;
	int tdListen, tcpd, inCnt, st;
	char rBuf[READBUFSZ];
	char devName[] = "TCP0";
	
	localAddr.ipAddr = 0;
	localAddr.sin_port = TCPPORT_ACCUVOTE;
	mc->cmdLen = 0;
	mc->commandFcn = monDump;
	tcpd = -1;
	
	if ((tdListen = tcpOpen()) < 0) {
		DIAGMONTRACE((LOG_ERR, "monitorMain[%d]: Unable to open TCP (%d)", 
					(int)md, tdListen));
	} else if ((inCnt = MONTCP_KEEPALIVE) != 0 
			&& (st = tcpIOCtl(tdListen, TCPCTLS_KEEPALIVE, &inCnt)) < 0) {
		DIAGMONTRACE((LOG_ERR, "monitorMain[%d]: Error %d setting keep alive", 
					(int)md, st));
	} else for (;;) {
		if ((st = tcpBind(tdListen, &localAddr)) < 0) {
			DIAGMONTRACE((LOG_ERR, "monitorMain[%d]: Error %d on bind", (int)md, st));
			break;
		} else if ((tcpd = tcpAccept(tdListen, &peerAddr)) < 0) {
			DIAGMONTRACE((LOG_ERR, "monitorMain[%d]: Error %d on accept", (int)md, tcpd));
			break;
		} else if (devName[3] = '0' + tcpd, (mc->fp = fopen(devName, "w+")) == NULL) {
			DIAGMONTRACE((LOG_ERR, "monitorMain[%d]: Error %d on fopen", (int)md, mc->fp));
			break;
		} else if ((st = fputs(MONPROMPT, mc->fp)) < 0 || fflush(mc->fp) < 0) {
			DIAGMONTRACE((LOG_ERR, "monitorMain[%d]: Error %d on write", (int)md, st));
			break;
		} else {
			DIAGMONTRACE((LOG_INFO, "monitorMain[%d]: connect %s:%u", (int)md,
						ip_ntoa(htonl(peerAddr.sin_addr.s_addr)),
						peerAddr.sin_port));
			inCnt = LOG_DETAIL;
			tcpIOCtl(tdListen, TCPCTLS_TRACELEVEL, &inCnt);
			while ((inCnt = tcpRead(tcpd, rBuf, READBUFSZ)) >= 0) {
				if ((st = tcpWrite(tcpd, rBuf, inCnt)) < 0) {
					DIAGMONTRACE((LOG_ERR, "monitorMain[%d]: Error %d on write", 
								(int)md, st));
					break;
				} else {
					(void)monProcInput(mc, rBuf, inCnt);
				}
			}
			DIAGMONTRACE((LOG_ERR, "monitorMain[%d]: Read=>%d st=%d", 
						(int)md, inCnt, st));
			inCnt = LOG_INFO;
			tcpIOCtl(tdListen, TCPCTLS_TRACELEVEL, &inCnt);
		}
		if (tcpd >= 0) {
			DIAGMONTRACE((LOG_INFO, "monitorMain[%d]: disconnect %d %s:%u", (int)md,
						tcpd,
						ip_ntoa(htonl(peerAddr.sin_addr.s_addr)),
						peerAddr.sin_port));
			if ((st = tcpDisconnect(tcpd)) < 0) {
				DIAGMONTRACE((LOG_ERR, "monitorMain[%d]: Disconnect err %d", 
							(int)md, st));
				break;
				
			} else if ((st = tcpWait(tcpd)) < 0) {
				DIAGMONTRACE((LOG_ERR, "monitorMain[%d]: Close wait err %d", 
							(int)md, st));
				break;
			}
		}
	}
	if (mc->fp != NULL) {
		DIAGMONTRACE((LOG_INFO, "monitorMain[%d]: closing", (int)md));
		fclose(mc->fp);
	}
	if (tdListen >= 0 && tdListen != tcpd) {
		DIAGMONTRACE((LOG_INFO, "monitorMain[%d]: disconnect %d %s:%u", (int)md, tdListen,
					ip_ntoa(htonl(peerAddr.sin_addr.s_addr)),
					peerAddr.sin_port));
		if ((st = tcpDisconnect(tdListen)) < 0) {
			DIAGMONTRACE((LOG_ERR, "monitorMain[%d]: Disconnect err %d", 
						(int)md, st));
		}
	}
	OSTaskDel(OS_PRIO_SELF);
}

#if DEBUGMONPORT > 0
/*
 * monitorMain1 - an interactive diagnostics monitor designed to be run as a
 * task connected via a serial port.
 */
static void monitorMain1(void *md)
{
	MonitorControl *mc = &monitorControl[(int)md];
	#define READBUFSZ 50
	FILE *fptr;
	int inCnt, st;
	char rBuf[READBUFSZ];
	
	mc->cmdLen = 0;
	mc->commandFcn = monDump;
	
	if ((mc->fp = fopen("COM1", "rw")) == NULL) {
		DIAGMONTRACE((LOG_ERR, "monitorMain[%d]: Unable to open sio (%d)", 
					(int)md, fptr));
	} else {
		inCnt = B9600;
		ioctl(fileno(mc->fp), SETBAUD, &inCnt);
		
		if ((st = write(fileno(mc->fp), MONPROMPT, MONPROMPTLEN)) < 0) {
			DIAGMONTRACE((LOG_ERR, "monitorMain[%d]: Error %d on write", (int)md, st));
		} else {
			while ((inCnt = read(fileno(mc->fp), rBuf, READBUFSZ)) >= 0) {
				if ((st = write(fileno(mc->fp), rBuf, inCnt)) < 0) {
					DIAGMONTRACE((LOG_ERR, "monitorMain[%d]: Error %d on write", 
								(int)md, st));
					break;
				} else {
					(void)monProcInput(mc, rBuf, inCnt);
				}
			}
		}
	}
	if (mc->fp != NULL) {
		DIAGMONTRACE((LOG_INFO, "monitorMain[%d]: closing", (int)md));
		fclose(mc->fp);
	}
	OSTaskDel(OS_PRIO_SELF);
}
#endif

/*
 * monProcInput - process incoming monitor data.  This function takes user
 * input to build the command line which when complete, is parsed and
 * executed.  Because this may be called with any fragment or even character
 * by character, it must maintain state in the monitor control block.
 * Return 0 on success, an error code on failure.
 */
static int monProcInput(MonitorControl *mc, char *rBuf, int inCnt)
{
	int st = 0;
	int curNdx;
	char c;
	
	for (curNdx = 0; st == 0 && curNdx < inCnt; curNdx++) {
		c = rBuf[curNdx];
		switch(c) {
		case '\r':
			if ((st = monParseCmd(mc)) < 0) {
				;
			} else if ((st = mc->commandFcn(mc)) < 0) {
				;
			} else if ((st = fputs(MONPROMPT, mc->fp)) < 0 || fflush(mc->fp) < 0) {
				DIAGMONTRACE((LOG_ERR, "monProcInput[%d]: Error %d on write errno=%d", 
							(int)(mc - &monitorControl[0]), st, errno));
			}
			mc->cmdLen = 0;
			break;
		case '\n':
			/* Ignore line feeds for now. */
			break;
		case '\b':
			if (mc->cmdLen > 0)
				mc->cmdLen--;
			break;
		default:
			if (mc->cmdLen < CMDLINESZ)
				mc->cmdBuf[mc->cmdLen++] = c;
		}
	}
	
	return st;
}

/*
 * monParseCmd - Parse the current command line.  This is called when an 
 *	end-of-line indication is reached.  This sets up the commmand parameters 
 *	for a call to the appropriate command handler.
 * Return 0 on success, an error code on failure.
 */
static int monParseCmd(MonitorControl *mc)
{
	int st = 0;
	int curNdx;
	char *tokenPtr;						/* Current token in command line. */
	int tokenLen = 0;					/* Current length of token. */
	char c;

	mc->parseFcn = parseCmdToken;
	mc->curTokenTbl = cmdToken;
	mc->sendStr = MONCMDLIST;
	mc->curCmdArgQty = 0;
	for (curNdx = 0; curNdx < MAXCMDARGS; curNdx++)
		mc->curCmdArgs[curNdx] = -1;
	
	for (curNdx = 0; st >= 0 && curNdx <= mc->cmdLen; curNdx++) {
		if (curNdx < mc->cmdLen)
			c = mc->cmdBuf[curNdx];
		else
			c = '\0';
		
		/*
		 * Alphanumerics are treated as strings separated by white space
		 * and operators/punctuation.
		 */
		if (isalnum(c)) {
			mc->cmdBuf[curNdx] = toupper(c);
			if (tokenLen++ == 0)
				tokenPtr = &mc->cmdBuf[curNdx];
		
		} else {
			/*
			 * Anything else is treated as white space which is used
			 * to delimit string tokens.
			 */
			if (tokenLen > 0) {
				st = mc->parseFcn(mc, tokenPtr, tokenLen);
				tokenLen = 0;
			}
			
			/*
			 * Handle special characters.  This could be a little more
			 * sophisticated and do a lookahead for multi-character
			 * operators but we'll worry about that when we need to.
			 */
			if (c && st >= 0 && (ispunct(c) || iscntrl(c))) {
				tokenPtr = &mc->cmdBuf[curNdx];
				st = mc->parseFcn(mc, tokenPtr, 1);
			}
		
		}
	}
	mc->cmdLen = 0;
	
	return st;
}


/*
 * parseCmdToken - Interpret a command token.  This is handled separately
 *	the command line arguments since there is no previous token table
 *	entry to define an error string for unrecognized commands.
 * Return 0 on success, an error code on failure.
 */
static int parseCmdToken(MonitorControl *mc, const char *tokenPtr, int tokenLen)
{
	const TokenTable *t0;
	int st = 0;
	
	if ((t0 = findToken(tokenPtr, tokenLen, cmdToken)) == NULL) {
		// Unrecognized command so display command list.
		mc->sendStr = MONCMDLIST;
		mc->commandFcn = monSendStr;
		mc->parseFcn = parseEOL;
		
	} else {
		mc->commandFcn = cmdFcn[t0->tokenValue];
		mc->curTokenTbl = t0->nextTbl;
		mc->parseFcn = t0->parseFcn;
		mc->sendStr = t0->errStr;
	}
	
	return st;
}

/*
 * parseCmdArg - Process a command argument.
 * Return 0 on success, an error code on failure.
 */
static int parseCmdArg(MonitorControl *mc, const char *tokenPtr, int tokenLen)
{
	const TokenTable *t0;
	int st = 0;
	
	if ((t0 = findToken(tokenPtr, tokenLen, mc->curTokenTbl)) == NULL) {
		// Unrecognized arguement so display error message.
		mc->commandFcn = monSendStr;
		mc->parseFcn = parseEOL;
		
	} else {
		if (t0->tokenLabel[0] == '%') {
			int tokVal = 0, i;
			
			switch(t0->tokenLabel[1]) {
			case 'd':
				for (i = 0; i < tokenLen && isdigit(tokenPtr[i]); i++)
					tokVal = tokVal * 10 + tokenPtr[i] - '0';
				// Ignore trailing non-digit characters.
				break;
			default:
				break;
			}
			mc->curCmdArgs[mc->curCmdArgQty++] = tokVal;
			
		} else
			mc->curCmdArgs[mc->curCmdArgQty++] = t0->tokenValue;
		mc->curTokenTbl = t0->nextTbl;
		mc->parseFcn = t0->parseFcn;
		mc->sendStr = t0->errStr;
	}
	
	return st;
}

/*
 * findToken - Do a linear search of the token table for the first token
 *	that matches the first tokenLen characters of the token buffer.
 * Return a pointer to the token table record if found, otherwise NULL.
 */
static const TokenTable *findToken(const char *tokenPtr, int tokenLen, const TokenTable *tt)
{
	const TokenTable *st = NULL, *t0;
	
	if (tt) {
		// Note: The last entry in a table must have an empty string for a label.
		for (t0 = tt; !st && t0->tokenLabel[0]; t0++) {
			// Handle simplified printf style format types as wild cards.
			if (t0->tokenLabel[0] == '%') {
				switch(t0->tokenLabel[1]) {
				case 'd':
					if (isdigit(tokenPtr[0]))
						st = t0;
					break;
				default:
					break;
				}
			
			// Otherwise require a perfect match.
			} else if (!strncmp(tokenPtr, t0->tokenLabel, tokenLen))
				st = t0;
		}
	}
		
	return st;
}
		

/*
 * parseEOL - Skip to the end of the command line.
 * Return 0 on success, an error code on failure.
 */
#pragma argsused
static int parseEOL(MonitorControl *mc, const char *tokenPtr, int tokenLen)
{
	/* Ignore everything! */
	return 0;
}

/*
 * monDump - Perform a dump command.  Dump is used to display a sequence of
 *	data that needs to be paginated.  The dump option is saved so that a
 *	dump command without an option repeats the last option.
 */
static int monDump(MonitorControl *mc)
{
	int st = 0;
	static int lastCmd = MONDUMP_TRACE;
	
	if (mc->curCmdArgQty > 0)
		lastCmd = mc->curCmdArgs[0];
	switch(lastCmd) {
	case MONDUMP_SCAN:
		scanDump(mc->fp, mc->curCmdArgs[1], mc->curCmdArgs[2]);
		break;
	case MONDUMP_TRACE:
	default:
		traceDump(mc->fp, mc->curCmdArgs[1], mc->curCmdArgs[2]);
		break;
	}
	fflush(mc->fp);
	
	return st;
}

/*
 * monSet - Perform a set command.
 */
static int monSet(MonitorControl *mc)
{
	int st = 0;
	
	switch(mc->curCmdArgs[0]) {
	case MONSET_TRACE:							/* Set the trace levels. */
		if (mc->curCmdArgQty < 2) {
			st = monSendMask(mc);
		} else {
			traceLevel[mc->curCmdArgs[1]] = mc->curCmdArgs[2];
		}
		break;
	default:
		mc->sendStr = MONSETOPTIONS;
		st = monSendStr(mc);
		break;
	}
	
	return st;
}

/*
 * monDisplay - Display a table.
 */
static int monDisplay(MonitorControl *mc)
{
	int st = 0;
	static int lastCmd = MONDISP_MCARD;
	
	if (mc->curCmdArgQty > 0)
		lastCmd = mc->curCmdArgs[0];
	switch(lastCmd) {
#if STATS_SUPPORT > 0
	case MONDISP_BUFFER:				/* Display the buffer statistics. */
		st = monSendStats(mc, (DiagStat *)&nBufStats);
		break;
	case MONDISP_TCP:					/* Display TCP session statistics. */
		st = monSendStats(mc, (DiagStat *)&tcpStats);
		break;
	case MONDISP_IP:					/* Display IP statistics. */
		st = monSendStats(mc, (DiagStat *)&ipStats);
		break;
	case MONDISP_PPP:					/* Display PPP session statistics. */
		st = monSendStats(mc, (DiagStat *)&pppStats);
		break;
	case MONDISP_SERIAL:				/* Display serial driver statistics. */
		st = monSendStats(mc, (DiagStat *)&sioStats);
		break;
#endif
	case MONDISP_MCARD:					/* Display memory card status*/
	default:
		memCardDump(mc->fp, 0, 1000);
		break;
	}
	
	return st;
}

static int monSendStr(MonitorControl *mc)
{
	int st;
	
	if ((st = write(fileno(mc->fp), mc->sendStr, strlen(mc->sendStr))) < 0) {
		DIAGMONTRACE((LOG_ERR, "monSendStr[%d]: Error %d on write errno=%d", 
					(int)(mc - &monitorControl[0]), st, errno));
	}
	
	return st;
}

/*
 * monSendMask - Send the trace mask.
 */
static int monSendMask(MonitorControl *mc)
{
	int st = 0, i, n;
	char sendBuf[SENDLINESZ + 1];	/* Extra for null termination. */
	
	strcpy(sendBuf, "\r\n\t\tMODULE TRACE LEVELS\r\n");
	n = strlen(sendBuf);
	mc->sendStr = sendBuf;
	/* Step through each of the trace modules. */
	for (i = 0; st >= 0 && i < TL_MAX;) {
		/* Build and send a buffer. */
		while (i < TL_MAX && n <= SENDLINESZ - 16) {
			sprintf(sendBuf + n, "\t%10s:%2u\r\n",
					maskModuleToken[i].tokenLabel,
					traceLevel[i]);
			n = strlen(sendBuf);
			i++;
		}
		st = monSendStr(mc);
		n = 0;
		sendBuf[0] = '\0';
	}
	
	return st >= 0 ? 0 : st;
}

/*
 * monSendStats - Send network statistics.
 */
static int monSendStats(MonitorControl *mc, DiagStat ds[])
{
	int st = 0, i, n;
	char sendBuf[SENDLINESZ + 1];	/* Extra for null termination. */
	char *strPtr;
	
	mc->sendStr = sendBuf;
	/* 
	 * Step through each of the statistics records until reaching one with an
	 * empty name. 
	 */
	for (i = 0; st >= 0 && ds[i].fmtStr && ds[i].fmtStr[0];) {
		/* Build and send a buffer. */
		n = 0;
		sendBuf[0] = '\0';
		while ((strPtr = ds[i].fmtStr) != NULL && *strPtr 
				&& n <= SENDLINESZ - (strlen(strPtr) + 10)) {
			sprintf(sendBuf + n, strPtr, ds[i].val);
			n = strlen(sendBuf);
			i++;
		}
		st = monSendStr(mc);
	}
	
	return st >= 0 ? 0 : st;
}


#endif


