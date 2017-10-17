/*****************************************************************************
* netauth.c - Network Authentication and Phase Control program file.
*
* Copyright (c) 1997 by Global Election Systems Inc.  All rights reserved.
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
*	Ported from public pppd code.
*****************************************************************************/
/*
 * auth.c - PPP authentication and phase control.
 *
 * Copyright (c) 1993 The Australian National University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the Australian National University.  The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Copyright (c) 1989 Carnegie Mellon University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Carnegie Mellon University.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "netconf.h"

#include <string.h>
#include "net.h"
#include "netbuf.h"
#include "nettimer.h"
#include "netfsm.h"
#include "netlcp.h"
#include "netpap.h"
#include "netchap.h"
#include "netauth.h"
#include "netppp.h"
#include "netipcp.h"

#if CBCP_SUPPORT > 0
#include "netcbcp.h"
#endif

#include <stdio.h>
#include "netdebug.h"


/*************************/
/*** LOCAL DEFINITIONS ***/
/*************************/

/* Bits in auth_pending[] */
#define PAP_WITHPEER	1
#define PAP_PEER	2
#define CHAP_WITHPEER	4
#define CHAP_PEER	8


                                                                    
/************************/
/*** LOCAL DATA TYPES ***/
/************************/
/* Used for storing a sequence of words.  Usually malloced. */
struct wordlist {
    struct wordlist	*next;
    char		word[1];
};



/***********************************/
/*** LOCAL FUNCTION DECLARATIONS ***/
/***********************************/
extern char *crypt __P((const char *, const char *));

/* Prototypes for procedures local to this file. */

static void network_phase __P((int));
static void check_idle __P((void *));
static void connect_time_expired __P((void *));
#ifdef XXX
static int  login __P((char *, char *, char **, int *));
#endif
static void logout __P((void));
static int  null_login __P((int));
static int  get_pap_passwd __P((int));
static int  have_pap_secret __P((void));
static int  have_chap_secret __P((char *, char *, u_int32_t));
static int  ip_addr_check __P((u_int32_t, struct wordlist *));
#if PAP_SUPPORT > 0 || CHAP_SUPPORT > 0
static void set_allowed_addrs(int unit, struct wordlist *addrs);
static void free_wordlist __P((struct wordlist *));
#endif
#if CBCP_SUPPORT > 0
static void callback_phase __P((int));
#endif


/******************************/
/*** PUBLIC DATA STRUCTURES ***/
/******************************/


/*****************************/
/*** LOCAL DATA STRUCTURES ***/
/*****************************/
#if PAP_SUPPORT > 0 || CHAP_SUPPORT > 0
/* The name by which the peer authenticated itself to us. */
static char peer_authname[MAXNAMELEN];
#endif

/* Records which authentication operations haven't completed yet. */
static int auth_pending[NUM_PPP];

/* Set if we have successfully called login() */
static int logged_in;

/* Set if we have run the /etc/ppp/auth-up script. */
static int did_authup;

/* List of addresses which the peer may use. */
static struct wordlist *addresses[NUM_PPP];

/* Number of network protocols which we have opened. */
static int num_np_open;

/* Number of network protocols which have come up. */
static int num_np_up;

#if PAP_SUPPORT > 0 || CHAP_SUPPORT > 0
/* Set if we got the contents of passwd[] from the pap-secrets file. */
static int passwd_from_file;
#endif



/***********************************/
/*** PUBLIC FUNCTION DEFINITIONS ***/
/***********************************/
/*
 * An Open on LCP has requested a change from Dead to Establish phase.
 * Do what's necessary to bring the physical layer up.
 */
#pragma argsused
void link_required(int unit)
{
	AUTHDEBUG((LOG_INFO, "link_required: %d", unit));
}

/*
 * LCP has terminated the link; go to the Dead phase and take the
 * physical layer down.
 */
#pragma argsused
void link_terminated(int unit)
{
	AUTHDEBUG((LOG_INFO, "link_terminated: %d", unit));
	
	if (lcp_phase[unit] == PHASE_DEAD)
		return;
	if (logged_in)
		logout();
	lcp_phase[unit] = PHASE_DEAD;
	trace(LOG_NOTICE, "Connection terminated.");
}

/*
 * LCP has gone down; it will either die or try to re-establish.
 */
void link_down(int unit)
{
	int i;
	struct protent *protp;
	
	AUTHDEBUG((LOG_INFO, "link_down: %d", unit));
	if (did_authup) {
		/* XXX Do link down processing. */
		did_authup = 0;
	}
	for (i = 0; (protp = protocols[i]) != NULL; ++i) {
		if (!protp->enabled_flag)
			continue;
		if (protp->protocol != PPP_LCP && protp->lowerdown != NULL)
			(*protp->lowerdown)(unit);
		if (protp->protocol < 0xC000 && protp->close != NULL)
			(*protp->close)(unit, "LCP down");
	}
	num_np_open = 0;
	num_np_up = 0;
	if (lcp_phase[unit] != PHASE_DEAD)
		lcp_phase[unit] = PHASE_TERMINATE;
}

/*
 * The link is established.
 * Proceed to the Dead, Authenticate or Network phase as appropriate.
 */
void link_established(int unit)
{
	int auth;
	int i;
	struct protent *protp;
	lcp_options *wo = &lcp_wantoptions[unit];
	lcp_options *go = &lcp_gotoptions[unit];
#if PAP_SUPPORT > 0 || CHAP_SUPPORT > 0
	lcp_options *ho = &lcp_hisoptions[unit];
#endif
	
	AUTHDEBUG((LOG_INFO, "link_established: %d", unit));
	/*
	 * Tell higher-level protocols that LCP is up.
	 */
	for (i = 0; (protp = protocols[i]) != NULL; ++i)
		if (protp->protocol != PPP_LCP && protp->enabled_flag
				&& protp->lowerup != NULL)
			(*protp->lowerup)(unit);
	
	if (auth_required && !(go->neg_chap || go->neg_upap)) {
		/*
		 * We wanted the peer to authenticate itself, and it refused:
		 * treat it as though it authenticated with PAP using a username
		 * of "" and a password of "".  If that's not OK, boot it out.
		 */
		if (!wo->neg_upap || !null_login(unit)) {
			trace(LOG_WARNING, "peer refused to authenticate");
			lcp_close(unit, "peer refused to authenticate");
			return;
		}
	}
	
	lcp_phase[unit] = PHASE_AUTHENTICATE;
	auth = 0;
#if CHAP_SUPPORT > 0
	if (go->neg_chap) {
		ChapAuthPeer(unit, our_name, go->chap_mdtype);
		auth |= CHAP_PEER;
	} 
#endif
#if PAP_SUPPORT > 0 && CHAP_SUPPORT > 0
	else
#endif
#if PAP_SUPPORT > 0
	if (go->neg_upap) {
		upap_authpeer(unit);
		auth |= PAP_PEER;
	}
#endif
#if CHAP_SUPPORT > 0
	if (ho->neg_chap) {
		ChapAuthWithPeer(unit, user, ho->chap_mdtype);
		auth |= CHAP_WITHPEER;
	}
#endif
#if PAP_SUPPORT > 0 && CHAP_SUPPORT > 0
	else
#endif
#if PAP_SUPPORT > 0
	if (ho->neg_upap) {
		if (passwd[0] == 0) {
			passwd_from_file = 1;
			if (!get_pap_passwd(unit))
				trace(LOG_ERR, "No secret found for PAP login");
		}
		upap_authwithpeer(unit, user, passwd);
		auth |= PAP_WITHPEER;
	}
#endif
	auth_pending[unit] = auth;
	
	if (!auth)
		network_phase(unit);
}


/*
 * The peer has failed to authenticate himself using `protocol'.
 */
#pragma argsused
void auth_peer_fail(int unit, int protocol)
{
	AUTHDEBUG((LOG_INFO, "auth_peer_fail: %d proto=%X", unit, protocol));
	/*
	 * Authentication failure: take the link down
	 */
	lcp_close(unit, "Authentication failed");
}


#if PAP_SUPPORT > 0 || CHAP_SUPPORT > 0
/*
 * The peer has been successfully authenticated using `protocol'.
 */
void auth_peer_success(int unit, int protocol, char *name, int namelen)
{
	int bit;
	
	AUTHDEBUG((LOG_INFO, "auth_peer_success: %d proto=%X", unit, protocol));
	switch (protocol) {
	case PPP_CHAP:
		bit = CHAP_PEER;
		break;
	case PPP_PAP:
		bit = PAP_PEER;
		break;
	default:
		trace(LOG_WARNING, "auth_peer_success: unknown protocol %x",
			   protocol);
		return;
	}
	
	/*
	 * Save the authenticated name of the peer for later.
	 */
	if (namelen > sizeof(peer_authname) - 1)
		namelen = sizeof(peer_authname) - 1;
	BCOPY(name, peer_authname, namelen);
	peer_authname[namelen] = 0;
	
	/*
	 * If there is no more authentication still to be done,
	 * proceed to the network (or callback) phase.
	 */
	if ((auth_pending[unit] &= ~bit) == 0)
		network_phase(unit);
}

/*
 * We have failed to authenticate ourselves to the peer using `protocol'.
 */
#pragma argsused
void auth_withpeer_fail(int unit, int protocol)
{
	int errCode = PPPERR_AUTHFAIL;
	
	AUTHDEBUG((LOG_INFO, "auth_withpeer_fail: %d proto=%X", unit, protocol));
	if (passwd_from_file)
		BZERO(passwd, MAXSECRETLEN);
	/* 
	 * XXX Warning: the unit number indicates the interface which is
	 * not necessarily the PPP connection.  It works here as long
	 * as we are only supporting PPP interfaces.
	 */
	pppIOCtl(unit, PPPCTLS_ERRCODE, &errCode);

	/*
	 * We've failed to authenticate ourselves to our peer.
	 * He'll probably take the link down, and there's not much
	 * we can do except wait for that.
	 */
}

/*
 * We have successfully authenticated ourselves with the peer using `protocol'.
 */
void auth_withpeer_success(int unit, int protocol)
{
	int bit;
	
	AUTHDEBUG((LOG_INFO, "auth_withpeer_success: %d proto=%X", unit, protocol));
	switch (protocol) {
	case PPP_CHAP:
		bit = CHAP_WITHPEER;
		break;
	case PPP_PAP:
		if (passwd_from_file)
		    BZERO(passwd, MAXSECRETLEN);
		bit = PAP_WITHPEER;
		break;
	default:
		trace(LOG_WARNING, "auth_peer_success: unknown protocol %x",
		       protocol);
		bit = 0;
	}
	
	/*
	 * If there is no more authentication still being done,
	 * proceed to the network (or callback) phase.
	 */
	if ((auth_pending[unit] &= ~bit) == 0)
		network_phase(unit);
}
#endif


/*
 * np_up - a network protocol has come up.
 */
#pragma argsused
void np_up(int unit, int proto)
{
	AUTHDEBUG((LOG_INFO, "np_up: %d proto=%X", unit, proto));
	if (num_np_up == 0) {
		/*
		 * At this point we consider that the link has come up successfully.
		 */
		if (idle_time_limit > 0)
			TIMEOUT(check_idle, NULL, idle_time_limit);
		
		/*
		 * Set a timeout to close the connection once the maximum
		 * connect time has expired.
		 */
		if (maxconnect > 0)
			TIMEOUT(connect_time_expired, 0, maxconnect);
	}
	++num_np_up;
}

/*
 * np_down - a network protocol has gone down.
 */
#pragma argsused
void np_down(int unit, int proto)
{
	AUTHDEBUG((LOG_INFO, "np_down: %d proto=%X", unit, proto));
	if (--num_np_up == 0 && idle_time_limit > 0) {
		UNTIMEOUT(check_idle, NULL);
	}
}

/*
 * np_finished - a network protocol has finished using the link.
 */
#pragma argsused
void np_finished(int unit, int proto)
{
	AUTHDEBUG((LOG_INFO, "np_finished: %d proto=%X", unit, proto));
	if (--num_np_open <= 0) {
		/* no further use for the link: shut up shop. */
		lcp_close(0, "No network protocols running");
	}
}

/*
 * auth_reset - called when LCP is starting negotiations to recheck
 * authentication options, i.e. whether we have appropriate secrets
 * to use for authenticating ourselves and/or the peer.
 */
void auth_reset(int unit)
{
	lcp_options *go = &lcp_gotoptions[unit];
	lcp_options *ao = &lcp_allowoptions[0];
	ipcp_options *ipwo = &ipcp_wantoptions[0];
	u_int32_t remote;
	
	AUTHDEBUG((LOG_INFO, "auth_reset: %d", unit));
	ao->neg_upap = !refuse_pap && (passwd[0] != 0 || get_pap_passwd(unit));
	ao->neg_chap = !refuse_chap	&& have_chap_secret(user, remote_name, (u_int32_t)0);
	
	if (go->neg_upap && !have_pap_secret())
		go->neg_upap = 0;
	if (go->neg_chap) {
		remote = ipwo->accept_remote? 0: ipwo->hisaddr;
		if (!have_chap_secret(remote_name, our_name, remote))
			go->neg_chap = 0;
	}
}


#if PAP_SUPPORT > 0
/*
 * check_passwd - Check the user name and passwd against the PAP secrets
 * file.  If requested, also check against the system password database,
 * and login the user if OK.
 *
 * returns:
 *	UPAP_AUTHNAK: Authentication failed.
 *	UPAP_AUTHACK: Authentication succeeded.
 * In either case, msg points to an appropriate message.
 */
int check_passwd(
	int unit,
	char *auser,
	int userlen,
	char *apasswd,
	int passwdlen,
	char **msg,
	int *msglen
)
{
	int ret = 0;
	struct wordlist *addrs = NULL;
	char passwd[256], user[256];
	char secret[MAXWORDLEN];
	static int attempts = 0;
	
	/*
	 * Make copies of apasswd and auser, then null-terminate them.
	 */
	BCOPY(apasswd, passwd, passwdlen);
	passwd[passwdlen] = '\0';
	BCOPY(auser, user, userlen);
	user[userlen] = '\0';
	*msg = (char *) 0;

	/* XXX Validate user name and password. */
	ret = UPAP_AUTHACK;		/* XXX Assume all entries OK. */
		
	if (ret == UPAP_AUTHNAK) {
		if (*msg == (char *) 0)
			*msg = "Login incorrect";
		*msglen = strlen(*msg);
		/*
		 * Frustrate passwd stealer programs.
		 * Allow 10 tries, but start backing off after 3 (stolen from login).
		 * On 10'th, drop the connection.
		 */
		if (attempts++ >= 10) {
			trace(LOG_WARNING, "%d LOGIN FAILURES BY %s", attempts, user);
			panic("Excess Bad Logins");
		}
		if (attempts > 3)
			sleep((UINT) (attempts - 3) * 5);
		if (addrs != NULL)
			free_wordlist(addrs);
	} else {
		attempts = 0;			/* Reset count */
		if (*msg == (char *) 0)
			*msg = "Login ok";
		*msglen = strlen(*msg);
		set_allowed_addrs(unit, addrs);
	}
	
	BZERO(passwd, sizeof(passwd));
	BZERO(secret, sizeof(secret));
	
	return ret;
}
#endif


/*
 * auth_ip_addr - check whether the peer is authorized to use
 * a given IP address.  Returns 1 if authorized, 0 otherwise.
 */
int auth_ip_addr(int unit, u_int32_t addr)
{
	return ip_addr_check(addr, addresses[unit]);
}

/*
 * bad_ip_adrs - return 1 if the IP address is one we don't want
 * to use, such as an address in the loopback net or a multicast address.
 * addr is in network byte order.
 */
int bad_ip_adrs(u_int32_t addr)
{
	addr = ntohl(addr);
	return (addr >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET
		|| IN_MULTICAST(addr) || IN_BADCLASS(addr);
}


#if CHAP_SUPPORT > 0
/*
 * get_secret - open the CHAP secret file and return the secret
 * for authenticating the given client on the given server.
 * (We could be either client or server).
 */
int get_secret(
	int unit,
	char *client,
	char *server,
	char *secret,
	int *secret_len,
	int save_addrs
)
{
	int ret = 0, len;
	struct wordlist *addrs;
	char secbuf[MAXWORDLEN];
	
	addrs = NULL;
	secbuf[0] = 0;

	/* XXX Find secret. */	
	if (ret < 0)
		return 0;
	
	if (save_addrs)
		set_allowed_addrs(unit, addrs);
	
	len = strlen(secbuf);
	if (len > MAXSECRETLEN) {
		trace(LOG_ERR, "Secret for %s on %s is too long", client, server);
		len = MAXSECRETLEN;
	}
	BCOPY(secbuf, secret, len);
	BZERO(secbuf, sizeof(secbuf));
	*secret_len = len;
	
	return 1;
}
#endif


#ifdef UNUSED
/*
 * auth_check_options - called to check authentication options.
 */
void auth_check_options(void)
{
	lcp_options *wo = &lcp_wantoptions[0];
	int can_auth;
	ipcp_options *ipwo = &ipcp_wantoptions[0];
	u_int32_t remote;
	
	/* Default our_name to hostname, and user to our_name */
	if (our_name[0] == 0 || usehostname)
		strcpy(our_name, hostname);
	if (user[0] == 0)
		strcpy(user, our_name);
	
	/* If authentication is required, ask peer for CHAP or PAP. */
	if (auth_required && !wo->neg_chap && !wo->neg_upap) {
		wo->neg_chap = 1;
		wo->neg_upap = 1;
	}
	
	/*
	 * Check whether we have appropriate secrets to use
	 * to authenticate the peer.
	 */
	can_auth = wo->neg_upap && have_pap_secret();
	if (!can_auth && wo->neg_chap) {
		remote = ipwo->accept_remote? 0: ipwo->hisaddr;
		can_auth = have_chap_secret(remote_name, our_name, remote);
	}
	
	if (auth_required && !can_auth) {
		panic("No auth secret");
	}
}
#endif


/**********************************/
/*** LOCAL FUNCTION DEFINITIONS ***/
/**********************************/
/*
 * Proceed to the network phase.
 */
static void network_phase(int unit)
{
	int i;
	struct protent *protp;
	lcp_options *go = &lcp_gotoptions[unit];
	
	/*
	 * If the peer had to authenticate, run the auth-up script now.
	 */
	if ((go->neg_chap || go->neg_upap) && !did_authup) {
		/* XXX Do setup for peer authentication. */
		did_authup = 1;
	}
	
#if CBCP_SUPPORT > 0
	/*
	 * If we negotiated callback, do it now.
	 */
	if (go->neg_cbcp) {
		lcp_phase[unit] = PHASE_CALLBACK;
		(*cbcp_protent.open)(unit);
		return;
	}
#endif
	
	lcp_phase[unit] = PHASE_NETWORK;
	for (i = 0; (protp = protocols[i]) != NULL; ++i)
		if (protp->protocol < 0xC000 && protp->enabled_flag
				&& protp->open != NULL) {
			(*protp->open)(unit);
			if (protp->protocol != PPP_CCP)
				++num_np_open;
		}
	
	if (num_np_open == 0)
		/* nothing to do */
		lcp_close(0, "No network protocols running");
}

/*
 * check_idle - check whether the link has been idle for long
 * enough that we can shut it down.
 */
#pragma argsused
static void check_idle(void *arg)
{
	struct ppp_idle idle;
	u_short itime;
	
	if (!get_idle_time(0, &idle))
		return;
	itime = MIN(idle.xmit_idle, idle.recv_idle);
	if (itime >= idle_time_limit) {
		/* link is idle: shut it down. */
		trace(LOG_INFO, "Terminating connection due to lack of activity.");
		lcp_close(0, "Link inactive");
	} else {
		TIMEOUT(check_idle, NULL, idle_time_limit - itime);
	}
}

/*
 * connect_time_expired - log a message and close the connection.
 */
#pragma argsused
static void connect_time_expired(void *arg)
{
	trace(LOG_INFO, "Connect time expired");
	lcp_close(0, "Connect time expired");	/* Close connection */
}

#ifdef XXX
/*
 * login - Check the user name and password against the system
 * password database, and login the user if OK.
 *
 * returns:
 *	UPAP_AUTHNAK: Login failed.
 *	UPAP_AUTHACK: Login succeeded.
 * In either case, msg points to an appropriate message.
 */
#pragma argsused
static int login(char *user, char *passwd, char **msg, int *msglen)
{
	/* XXX Fail until we decide that we want to support logins. */
	return (UPAP_AUTHNAK);
}
#endif

/*
 * logout - Logout the user.
 */
static void logout(void)
{
	logged_in = FALSE;
}


/*
 * null_login - Check if a username of "" and a password of "" are
 * acceptable, and iff so, set the list of acceptable IP addresses
 * and return 1.
 */
#pragma argsused
static int null_login(int unit)
{
	/* XXX Fail until we decide that we want to support logins. */
	return FALSE;
}


/*
 * get_pap_passwd - get a password for authenticating ourselves with
 * our peer using PAP.  Returns 1 on success, 0 if no suitable password
 * could be found.
 */
static int get_pap_passwd(int unit)
{
	return upap[unit].us_user[0] != '\0';
}


/*
 * have_pap_secret - check whether we have a PAP file with any
 * secrets that we could possibly use for authenticating the peer.
 */
static int have_pap_secret(void)
{
	/* XXX Fail until we set up our passwords. */
	return 0;
}


/*
 * have_chap_secret - check whether we have a CHAP file with a
 * secret that we could possibly use for authenticating `client'
 * on `server'.  Either can be the null string, meaning we don't
 * know the identity yet.
 */
#pragma argsused
static int have_chap_secret(char *client, char *server, u_int32_t remote)
{
	/* XXX Fail until we set up our passwords. */
	return 0;
}


#if PAP_SUPPORT > 0 || CHAP_SUPPORT > 0
/*
 * set_allowed_addrs() - set the list of allowed addresses.
 */
static void set_allowed_addrs(int unit, struct wordlist *addrs)
{
	if (addresses[unit] != NULL)
		free_wordlist(addresses[unit]);
	addresses[unit] = addrs;

#ifdef XXX
	/*
	 * If there's only one authorized address we might as well
	 * ask our peer for that one right away
	 */
	if (addrs != NULL && addrs->next == NULL) {
		char *p = addrs->word;
		struct ipcp_options *wo = &ipcp_wantoptions[unit];
		u_int32_t a;
		struct hostent *hp;
		
		if (wo->hisaddr == 0 && *p != '!' && *p != '-'
				&& strchr(p, '/') == NULL) {
			hp = gethostbyname(p);
			if (hp != NULL && hp->h_addrtype == AF_INET)
				a = *(u_int32_t *)hp->h_addr;
			else
				a = inet_addr(p);
			if (a != (u_int32_t) -1)
				wo->hisaddr = a;
		}
	}
#endif
}
#endif

static int ip_addr_check(u_int32_t addr, struct wordlist *addrs)
{
	
	/* don't allow loopback or multicast address */
	if (bad_ip_adrs(addr))
		return 0;
	
	if (addrs == NULL)
		return !auth_required;		/* no addresses authorized */
	
	/* XXX All other addresses allowed. */
	return 1;
}

#if PAP_SUPPORT > 0 || CHAP_SUPPORT
/*
 * free_wordlist - release memory allocated for a wordlist.
 */
static void free_wordlist(struct wordlist *wp)
{
	struct wordlist *next;
	
	while (wp != NULL) {
		next = wp->next;
		free(wp);
		wp = next;
	}
}
#endif

