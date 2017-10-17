/*****************************************************************************
* net.c - Network Globals program file.
*
* portions Copyright (c) 1997 by Global Election Systems Inc.
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
* 97-12-08 Guy Lancaster <lancasterg@acm.org>, Global Election Systems Inc.
*	Original.
*****************************************************************************/

#include "netconf.h"
#include "net.h"
#include <string.h>
#include "netbuf.h"
#include "netrand.h"
#include "netppp.h"
#include "netip.h"
#include "nettcp.h"

#include <stdio.h>
#include "netdebug.h"


/******************************/
/*** PUBLIC DATA STRUCTURES ***/
/******************************/
u_short	idle_time_limit = 0;	/* Disconnect if idle for this many seconds */
int	maxconnect = 0;				/* Maximum connect time */
int	refuse_pap = 0;				/* Don't wanna auth. ourselves with PAP */
int	refuse_chap = 0;			/* Don't wanna auth. ourselves with CHAP */

char hostname[MAXNAMELEN + 1];	/* Our hostname */
char user[MAXNAMELEN + 1];		/* Username for PAP */
char passwd[MAXSECRETLEN + 1];	/* Password for PAP */
char our_name[MAXNAMELEN + 1];	/* Our name for authentication purposes */
char remote_name[MAXNAMELEN + 1]; /* Peer's name for authentication */
int	explicit_remote = 0;		/* remote_name specified with remotename opt */
int	usehostname = 0;			/* Use hostname for our_name */

u_int32_t	netMask;			/* IP netmask to set on interface */
u_int32_t	localHost;			/* Our IP address in */


/***********************************/
/*** PUBLIC FUNCTION DEFINITIONS ***/
/***********************************/
/*
 * netInit - Initialize the network communications subsystem.
 */
void netInit(void)
{
	strcpy(hostname, LOCALHOST);
	user[0] = '\0';
	passwd[0] = '\0';
	our_name[0] = '\0';
	remote_name[0] = '\0';
	explicit_remote = 0;
	magicInit();
	ipInit();
	pppInit();
	tcpInit();
}

/*
 * Set the login user name and password for login and authentication
 *	purposes.  Using globals this way is rather hokey but until we
 *	fix some other things (like implementing a 2 stop PPP open),
 *	this will do for now.
 */
void netSetLogin(const char *luser, const char *lpassword)
{
	strncpy(user, luser, MAXNAMELEN);
	user[MAXNAMELEN] = '\0';
	strncpy(passwd, lpassword, MAXNAMELEN);
	passwd[MAXNAMELEN] = '\0';
}

/*
 * gethostbyname - Look up host name.
 * Return host's netent if found, otherwise NULL.
 */
#pragma argsused
struct hostent	*gethostbyname (const char *hn)
{
	return NULL;
}


/* Convert a host long to a network long.  */
u_long htonl (u_long __arg)
{
#if BYTE_ORDER == LITTLE_ENDIAN
#if USE_ASM
	asm {
		mov  ax, word ptr [__arg];
		xchg ah, al;
		xchg ax, word ptr [__arg + 2];
		xchg ah, al;
		mov  word ptr [__arg], ax;
	}
	return __arg;
#else
	union {
		u_int32_t w;
		char c[4];
	} u;
	char t;

	u.w = __arg;
	t = u.c[0];
	u.c[0] = u.c[3];
	u.c[3] = t;
	t = u.c[1];
	u.c[1] = u.c[2];
	u.c[2] = t;

	return u.w;
#endif
#endif
}

/* Convert a host short to a network short.  */
u_short htons (u_short __arg)
{
#if BYTE_ORDER == LITTLE_ENDIAN
#if USE_ASM
	asm {
		mov  ax, word ptr [__arg];
		xchg ah, al;
		mov  word ptr [__arg], ax;
	}
	return __arg;
#else
	union {
		u_int16_t w;
		char c[2];
	} u;
	char t;

	t = u.c[1];
	u.c[1] = u.c[2];
	u.c[2] = t;

	return u.w;
#endif
#endif
}


/*
 * print_string - print a readable representation of a string using
 * printer.
 */
void print_string(
	char *p,
	int len,
	void (*printer) __P((void *, char *, ...)),
	void *arg
)
{
	int c;
	
	printer(arg, "\"");
	for (; len > 0; --len) {
		c = *p++;
		if (' ' <= c && c <= '~') {
			if (c == '\\' || c == '"')
				printer(arg, "\\");
			printer(arg, "%c", c);
		} else {
			switch (c) {
			case '\n':
				printer(arg, "\\n");
				break;
			case '\r':
				printer(arg, "\\r");
				break;
			case '\t':
				printer(arg, "\\t");
				break;
			default:
				printer(arg, "\\%.3o", c);
			}
		}
	}
	printer(arg, "\"");
}


#if XXX
/*
 * bcmp - Compare a string of bytes and return non-zero if they differ.
 * Note: This differs from strncmp() in that nulls are not recognized
 *    as delimiters.
 */
int bcmp(u_char *s0, u_char *s1, int len)
{
	for (len--; len >= 0; len--)
		if (s0[len] != s1[len])
			return -1;
	return 0;
}
#endif

