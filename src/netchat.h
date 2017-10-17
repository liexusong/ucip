/*****************************************************************************
* NETCHAT.H - Communications Dialog (Chat) Header File.
*
* Copyright (c) 1996,1998 Global Election Systems Inc.
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
* 98-06-16 Guy Lancaster <glanca@gesn.com>, Global Election Systems Inc.
*****************************************************************************/

#ifndef CHAT_H
#define CHAT_H


/***********************
*** PUBLIC FUNCTIONS ***
***********************/
/*
 * Send a string and wait a limited time for one of a list of up to MAXRESPONSE
 *	possible responses.
 * Returns: >= 0 if successful as the index of the matching response string,
 *		-1 if timed out, or -2 if aborted by user pressing the NO button.
 */
int sendRecv(int fd, const char *sendStr, UINT timeLimit, UINT respStrQty, ...);

#endif

