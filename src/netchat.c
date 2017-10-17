/*****************************************************************************
* NETCHAT.C - Communications Dialog (Chat) Code File.
*
* Copyright (c) 1996, 1998 by Global Election Systems Inc.
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
* 98-06-16 Guy Lancaster <lancasterg@acm.org>, Global Election Systems Inc.
*****************************************************************************/

#include "netconf.h"
#include <string.h>

#include "netchat.h"

#include <stdio.h>
#include "netdebug.h"


/*************************/
/*** LOCAL DEFINITIONS ***/
/*************************/
#define MAXFLUSH 1000			/* Max characters to flush before sendRecv(). */
#define RECVBUFSZ 100			/* Size of the receive buffer. */
#define MAXRESPONSE 10			/* Max response strings that sendRecv() can match. */

// Pattern matching states.
#define PMSKIPSOURCE 5
#define PMSKIPPATTERN 4
#define PMMULTIPLYING 3
#define PMTRYNEXT 2
#define PMMATCHING 1
#define PMINITIALIZE 0
#define PMSUCCESS -1
#define PMFAIL -2


/************************/
/*** LOCAL DATA TYPES ***/
/************************/
typedef struct patternContext_s {
	int  st;					/* The pattern matching status. */
	char *patStr;				/* The pattern string to match. */
	UINT patNdx;				/* Index to the pattern string. */
	UINT sourceNdx;				/* Index to the source string. */
	UINT matchNdx;				/* Index to the source string. */
} PatternContext;


/***********************************/
/*** LOCAL FUNCTION DECLARATIONS ***/
/***********************************/
static PatternContext *copyPattern(PatternContext *srcPat, PatternContext *destPat,
                                      int srcOffset, int matchOffset, int patOffset);
static int tryNextSource(PatternContext *respPat);
static int matchEOL(char *sourceStr, PatternContext *respPat);
static int matchCurrent(char *sourceStr, PatternContext *respPat);
static int patternMatch(char *sourceStr, PatternContext *respPat) ;


/***********************************/
/*** PUBLIC FUNCTION DEFINITIONS ***/
/***********************************/
/* Send a string to the modem and wait a limited time for one of a list of
 *	up to MAXRESPONSE possible responses.
 * Returns: >= 0 if successful as the index of the matching response string,
 *		-1 if timed out, or -2 if aborted by user pressing the NO button.
 */
int sendRecv(int fd, const char *sendStr, UINT timeLimit, UINT respStrQty, ...)
{
	int  i, st, curChar;
	int finished = FALSE;
	char recvBuf[RECVBUFSZ];			/* The receive buffer and index. */
	UINT recvNdx;
    PatternContext respPat[MAXRESPONSE];	/* Response pattern structures. */
    PatternContext *curRespPat;
	void *arg;
	LONG timeOut = timeLimit * 100;		/* Time limit converted to milliseconds. */

	CHATTRACE((LOG_INFO, TL_CHAT, "sendRecv: s=[%Z] t=%d q=%d", 
				sendStr, timeLimit, respStrQty));

	/* Flush the input buffer up to MAXFLUSH characters. */
	st = 0;
	while ((i = read(fd, recvBuf, RECVBUFSZ - 1)) > 0) {
		st += i;
		if (st >= MAXFLUSH) {
			CHATTRACE((LOG_ERR, TL_CHAT, "sendRecv: Too much garbage from device %d", fd));
			st = -1;
			finished = TRUE;
		} else {
			recvBuf[min(i, RECVBUFSZ - 1)] = '\0';
			CHATTRACE((LOG_DEBUG, TL_CHAT,"sendRecv: flushed[%.30Z]", recvBuf));
		}
	}
	
	/* Send string to device if not null. */
	if (!finished && sendStr != NULL && sendStr[0] != '\0') {
		CHATTRACE((LOG_INFO, TL_CHAT, "sendRecv: sending [%Z]", sendStr));
		i = strlen(sendStr);
		if (write(fd, sendStr, i) != i ) {
			CHATTRACE((LOG_ERR, TL_CHAT, "sendRecv: Error sending [%Z] to %d", 
						sendStr, fd));
			st = -1;
			finished = TRUE;
		}
	}

	/* Set up for matching the response strings. */
	arg = &respStrQty;
	((int *)arg)++;		/* Assume that UINT pushed as an int on target machine. */
	if (respStrQty >= MAXRESPONSE) {
		CHATTRACE((LOG_WARNING, TL_CHAT, "sendRecv: WARNING! Ignoring extra response strings"));
		respStrQty = MAXRESPONSE;
	}
#if TRACECHAT > 0
	recvNdx = 0;
#endif
	for (i = 0; i < respStrQty; i++) {
		curRespPat = &respPat[i];
		curRespPat->st = 0;	/* Initialize */
		curRespPat->patStr = *((char **)arg)++;
		curRespPat->patNdx = 0;
		curRespPat->sourceNdx = 0;
		curRespPat->matchNdx = 0;
#if TRACECHAT > 0
		sprintf(&recvBuf[recvNdx], " p%d=[%Z]", i, respPat[i].patStr);
		recvNdx = strlen(recvBuf);
		if (recvNdx >= RECVBUFSZ - 32 || recvNdx >= 50) {
			CHATTRACE((LOG_INFO, TL_CHAT, "sendRecv: %s", recvBuf));
			recvNdx = 0;
		}
#endif
	}
#if TRACECHAT > 0
	if (recvNdx > 0) {
		CHATTRACE((LOG_INFO, TL_CHAT, "sendRecv: %s", recvBuf));
	}
#endif

	/* Wait limited time for response. */
	recvNdx = 0;
	recvBuf[0] = '\0';
	while (!finished) {
		/* Abort if user presses the NO button. */
		if (buttonNoStatus() == NOBUTTON) {
			CHATTRACE((LOG_ERR, TL_CHAT, "sendRecv: User abort!"));
			st = -2;
			finished = TRUE;
        /* Read next character. */
		} else if ((i = read(fd, &curChar, 1)) == 1) {
			/* Trap ^C as abort character. */
			if (curChar == '\003') {
				st = -2;
				finished = TRUE;
			} else if (curChar > 0) {
				recvBuf[recvNdx++] = curChar;
				recvBuf[recvNdx] = '\0';
				timeOut--;		/* Assume a character takes at least a millisecond. */
				for (i = 0; i < respStrQty && !finished; i++) {
					if (patternMatch(recvBuf, &respPat[i]) == 0) {
						st = i;
						finished = TRUE;
					}
				}
			}
        /* Abort if read failed. */
		} else if (i < -1) {
			CHATTRACE((LOG_ERR, TL_CHAT, "sendRecv: Error reading from %d", fd));
			st = -2;		/* Assume user pressed NO button to generate error. */
			finished = TRUE;
		/* Abort if timed out. */
		} else if (timeOut <= 0) {
			CHATTRACE((LOG_DETAIL, TL_CHAT, "sendRecv:abort due to timeout"));
			st = -1;			/* Time out */
			finished = TRUE;
		/* Wait for 100ms but abort if NO button pressed. */
		} else if (prompt(NOBUTTON, 100, NULL) == NOBUTTON) {
			CHATTRACE((LOG_ERR, TL_CHAT, "sendRecv: User aborted reading from %d", fd);)
			st = -2;
			finished = TRUE;
		/* Decrement the timer. */
		} else
			timeOut -= 100;
	}
	// Trace shows the last 20 bytes received if it'll fit.
#if TRACECHAT > 0
	i = MIN(recvNdx, 20);
	if (i == 0) i = 1;
#endif
	CHATTRACE((LOG_INFO, TL_CHAT, "sendRecv: [%*.*Z] => %d",
	           i, LOGMSGLEN - 25, &recvBuf[recvNdx - i], st));
	return st;
}


/**********************************/
/*** LOCAL FUNCTION DEFINITIONS ***/
/**********************************/
/*
 *	Copy the source pattern into the destination pattern and add the source, match and
 *	pattern offsets to the corresponding indexes.
 *	Return the destination pattern.
 */
static PatternContext *copyPattern(PatternContext *srcPat, PatternContext *destPat,
                                      int srcOffset, int matchOffset, int patOffset)
{
	destPat->st = srcPat->st;
	destPat->patStr = srcPat->patStr;
	destPat->patNdx = srcPat->patNdx + patOffset;
	destPat->sourceNdx = srcPat->sourceNdx + srcOffset;
	destPat->matchNdx = srcPat->matchNdx + matchOffset;
	return destPat;
}

/*
 *	The pattern has failed from the current source start position so check that
 *	the pattern allows us to try again later in the source.
 */
static int tryNextSource(PatternContext *respPat)
{
	respPat->st = PMMATCHING;
	
	/* If the pattern string begins with a caret, the pattern must match from the start of
		the source string. */
	if (respPat->patStr[0] == '^') {
		/* If we haven't tried without the caret, skip the caret and try again. */
		if (respPat->patNdx == 0 && respPat->sourceNdx == 0) {
			respPat->patNdx = 1;
			respPat->matchNdx = 0;
		/* We've tried once so now we fail. */
		} else {
			respPat->st = PMFAIL;
		}
	/* The match failed from the current start position so advance to the next start
		position and try again. */
	} else {
		respPat->patNdx = 0;
		respPat->sourceNdx++;
		respPat->matchNdx = respPat->sourceNdx;
	}
	return respPat->st;
}

/*
 *	Attempt to match the end-of-line '$' character.
 */
static int matchEOL(char *sourceStr, PatternContext *respPat)
{
	char curSource = sourceStr[respPat->matchNdx];
		
	/* Note: We don't want to advance the source if we're at the end of the string
	 *	because we will want to check from the same position the next time a character
	 *	is appended.  We ignore a single carriage return character until we're on the
	 *	next source character and then determine if it is combined with a line feed
	 *	character. */
	if (curSource == '\r') {
		if (respPat->matchNdx > 0 && sourceStr[respPat->matchNdx - 1] == '\r') {
			/* We've matched on a carriage return character and the previous character
			 *	is another carriage return character so this end-of-line pattern
			 *	matches the previous one.  Keep the default status. */
			;
		} else if (respPat->patStr[respPat->patNdx + 1] == '\0' &&
		         sourceStr[respPat->matchNdx + 1] == '\0') {
			/* SPECIAL CASE: This is the end of the source and pattern strings so we've
			 *	got a match. */
			respPat->st = PMSUCCESS;
		} else {
			/* Otherwise ignore this. */
			respPat->st = PMSKIPSOURCE;
		}
	} else if (curSource == '\n') {
		/* We've matched a line feed character which satisfies the end-of-line pattern.
		 *	Keep the default status. */
	} else if (respPat->matchNdx > 0 && sourceStr[respPat->matchNdx - 1] == '\r') {
		/* The previous character is a carriage return that we skipped above so it
		 *	matches this end-of-line pattern. */
		/* Note: This also correctly breaks out of a multiplier. */
		respPat->st = PMSKIPPATTERN;
	} else {
		/* We failed to match the end-of-line from the current position so try the next. */
		respPat->st = PMTRYNEXT;
	}

	return respPat->st;
}


/*
 *	Attempt to match the current pattern position with the current source position.
 *	Return the new pattern status.
 */
static int matchCurrent(char *sourceStr, PatternContext *respPat)
{
	int i;
	char curPattern, curSource;
	PatternContext tmpPat;		/* For recursive matching. */

	/* Load the current characters to match. */
	curSource = sourceStr[respPat->matchNdx];
	if (respPat->patNdx > 0 && 
	    (respPat->patStr[respPat->patNdx] == '*' || respPat->patStr[respPat->patNdx] == '+')) {
		/* We're matching a multiplier that isn't the first character of a 
		 *	pattern so load the previous pattern character and set status for
		 *	a multiplier.  Ideally we would just keep the previous pattern in case it wasn't
		 *	a single character pattern but we have no way of carrying that between calls. */
		curPattern = respPat->patStr[respPat->patNdx - 1];
		respPat->st = PMMULTIPLYING;
	} else {
		/* Load the new pattern and assume that we're going to match. */
		curPattern = respPat->patStr[respPat->patNdx];
		respPat->st = PMMATCHING;
	}
	
	if (curPattern == '\0') {
		/* We've matched the entire pattern so return success. */
		respPat->st = PMSUCCESS;
	} else if (curSource == '\0') {
		/* We've reached the end of the source buffer without matching the pattern
		 *	so return failure. */
		respPat->st = PMFAIL;
	} else if (curPattern == '\\') {
		if (curSource == respPat->patStr[respPat->patNdx + 1]) {
			/* We've matched an escaped special character so skip the escape and 
			 *	take the default status. */
			respPat->patNdx++;
		}
		else {
			/* The escaped character failed to match. */
			respPat->st = PMTRYNEXT;
		}
	} else if (respPat->st == PMMULTIPLYING &&
	         ((i = matchCurrent(sourceStr, copyPattern(respPat, &tmpPat, 0, 0, 1))) == PMMATCHING ||
	          i == PMSUCCESS)) {
		/* We're multiplying this pattern character and the next pattern matches this source
		 *	so break out of the multiplier. */
		respPat->st = PMSKIPPATTERN;
	} else if (curPattern == '$') {
		/* We're matching the end-of-line pattern. */
		respPat->st = matchEOL(sourceStr, respPat);
	} else if (curSource == curPattern) {
		/* We have a literal match so keep the default status. */
	} else if (respPat->patStr[respPat->patNdx + 1] == '*') {
		/* We have failed to match a non-wild pattern. The next pattern character is the
		 *	'*' multiplier so check for a zero length match. */
		if (curPattern != '.' || 
		    ((i = matchCurrent(sourceStr, copyPattern(respPat, &tmpPat, 0, 0, 2))) == PMMATCHING ||
		     i == PMSUCCESS)) {
			/* Either the current pattern is the wild character '.' and the next pattern
			 *	character matches this source which breaks the multiplier or the current
			 *	pattern doesn't match the current source so skip the multiplier. */
			respPat->patNdx++;
			respPat->st = PMSKIPPATTERN;
		} else {
			/* The current pattern is the wild character with a multiplier and the current
			 *	source doesn't match so we match on the wild character. */
		}
			
	} else if (curPattern == '.') {
		/* The wild character always matches so keep the default status. */
	} else {
		/* We've failed to find a match so try the next source position. */
		respPat->st = PMTRYNEXT;
	}
	
	CHATTRACE((LOG_DEBUG, TL_CHAT, "matchCurrent: s=[%Z] @%d,%d=%z p=[%Z] @%d=%z st=%d",
	        &sourceStr[respPat->sourceNdx], respPat->sourceNdx, respPat->matchNdx, curSource,
	        respPat->patStr, respPat->patNdx, curPattern, respPat->st));

	return respPat->st;
}


/*
 *	Attempt to match the pattern in the source string.  The pattern contains
 *	a pattern string composed of a subset of the UNIX regular expression
 *	characters.  Specifically it handles the '.' wild character and, to some
 *	degree, the '*' and '+' multipliers.  It also handles the '^' start-of-line
 *	character to mean the start of the source string and the '$' end-of-line
 *	character to mean a carriage return or line feed character or a carriage
 *	return-line feed combination.  The '\' escape character can be used before
 *	each of these special characters or itself to require that character to be
 *	matched literally.
 *
 *	This function is designed to be called for several different patterns
 *	each time a new character is added to the source string until one of the
 *	patterns match.  Thus the PatternContext structure maintains state information
 *	so that minimal previous work is repeated on each invocation.  Also, the
 *	interpretation of some of the pattern situations is modified so that a
 *	match is made early.  In particular, normally a regular expression is to
 *	match the largest input string possible from the source.  However, in our
 *	case we want the earliest match so that using the '.*x' sequence will exit
 *	on the next 'x' found in the string and no other possible matches will
 *	be attempted if the pattern fails later.  Thus the '.*' pattern must be
 *	used with caution.
 *
 *	Be especially aware that the first pattern character after the '.*' pattern
 *	will break the '.*' match.  Thus finding "t.*ing" in "this is icing" will
 *	fail because the 'i' matched the 'i' in "this".
 *
 *	Currently the patterns '**', '^*' (at the begining of a pattern), and
 *	'$*' will not work as expected since sometimes the special characters
 *	are interpretted and sometimes not.
 *
 *	Note: We cannot currently multiply escaped characters.
 *
 *	Returns: 0 on success, otherwise non-zero.
 */
static int patternMatch(char *sourceStr, PatternContext *respPat) 
{

	/* Attempt to match the rest of the pattern. */
	do {
		switch(matchCurrent(sourceStr, respPat)) {
		
		case PMMULTIPLYING:
			/* The pattern has a multiplier so just advance the source. */
			respPat->matchNdx++;
			respPat->st = PMMATCHING;
			break;
		case PMMATCHING:
			/* The pattern matched so advance the source and the pattern. */
			respPat->matchNdx++;
			respPat->patNdx++;
			respPat->st = PMMATCHING;
			break;
		case PMSKIPSOURCE:
			/* The current pattern has not completed so the source is being absorbed. */
			respPat->matchNdx++;
			respPat->st = PMMATCHING;
			break;
		case PMSKIPPATTERN:
			/* The current source starts a new pattern so skip the current pattern. */
			respPat->patNdx++;
			respPat->st = PMMATCHING;
			break;
		case PMTRYNEXT:
			/* We've failed from the current position in the source. */
			respPat->st = tryNextSource(respPat);
			break;
		default:
			/* Do nothing - we should be exitting. */
			break;
		}
	} while (respPat->st > 0);
	CHATTRACE((LOG_DEBUG, TL_CHAT, "patternMatch: st=%d => %d", 
	        respPat->st, (respPat->st == PMSUCCESS ? 0 : -1)));
	return (respPat->st == PMSUCCESS ? 0 : -1);
}



