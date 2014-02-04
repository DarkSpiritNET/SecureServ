/* NeoStats - IRC Statistical Services 
** Copyright (c) 1999-2005 Adam Rutter, Justin Hammond, Mark Hetherington
** http://www.neostats.net/
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
**  USA
**
** NeoStats CVS Identification
** $Id: scan.c 416 2007-08-21 02:50:25Z Fish $
*/

#include "SecureServ.h"
#include "updates.h"

#define MAX_VIRI LISTCOUNT_T_MAX

typedef struct virustype {
	int trigcount;
	int actcount;
	int defcount;
} virustype;

static virustype virustypes[MAX_PATTERN_TYPES];

static const char* dettypes[] =
{
	"ctcp version",
	"privmsg",
	"nick",
	"ident",
	"real name",
	"channel name",
	"channel message",
	"away message",
	"quit message",
	"topic",
	"built-in",
};

static const char* acttypes[] =
{
	"SVSjoin",
	"Akill",
	"Warn",
	"Nothing",
	"Kill",
};

static virientry builtin_fizzer =
{
	"FizzerBot",
	DET_BUILTIN,
	0,
	0,
	"",
	"User name is real name reversed",
	NULL,
	NULL,
	"You're infected with the fizzer virus",
	ACT_AKILL,
	0,
	0
};

/* List of local dat files that we will load and process
*/
static const char* DatFiles[NUM_DAT_FILES]=
{
	VIRI_DAT_NAME,
	CUSTOM_DAT_NAME,
};

/* this is the list of viri */
static list_t *viri[DET_MAX];

static void gotpositive(Client *u, virientry *ve, int type);

void InitScanner(void)
{
	int i;

	SET_SEGV_LOCATION();
	/* init the virus lists */
	for(i = 0; i < DET_MAX; i++)
		viri[i] = list_create(MAX_VIRI);
	load_dat();
}

void ScanStatus (const CmdParams *cmdparams)
{
	int i;
	
	irc_prefmsg (ss_bot, cmdparams->source, "Virus Patterns: %d", SecureServ.defcount);
	irc_prefmsg (ss_bot, cmdparams->source, "Type:             Scanned  Acted On Definitions");
	for( i = 0; i < DET_MAX; i++ )
	{
		irc_prefmsg (ss_bot, cmdparams->source, "%-15s %9d %9d   %9d", dettypes[i], virustypes[i].trigcount, virustypes[i].actcount, virustypes[i].defcount);
	}
}

/* This function will load viri.dat then try to load custom.dat 
   For custom entries, the lack of file is of no importance and a flag is set
   in the viri entry to indicate the custom nature of the definition for use
   by SecureServ.
*/

void load_dat(void) 
{
	static char buf[BUFSIZE];
	int i;
	FILE *fp;
	virientry *viridet;
	lnode_t *node;
	const char *error;
	int errofset;
	pcre *re;
	int rc;
	int ovector[24];
	const char **subs;

	SET_SEGV_LOCATION();
	/* if the list isn't empty, make it empty */
	for(i = 0; i < DET_MAX; i++) {
		if (!list_isempty(viri[i])) {
			node = list_first(viri[i]);
			while (node) {
				viridet = lnode_get(node);
				if(viridet) {
					dlog (DEBUG1, "Deleting %s out of List", viridet->name);
					if (viridet->pattern) {
						ns_free (viridet->pattern);
					}
					if (viridet->patternextra) {
						ns_free (viridet->patternextra);
					}
					ns_free (viridet);
				}
				node = list_next(viri[i], node);
			} 
			list_destroy_nodes(viri[i]);
		}
	}
	SecureServ.defcount = 0;	
	for (rc = 0; rc < MAX_PATTERN_TYPES; rc++) {
		virustypes[rc].defcount = 0;
	}	

	/* first, add the dat for Fizzer (even if its not enabled!) */
	viridet = ns_calloc (sizeof(virientry));
	os_memcpy (viridet, &builtin_fizzer, sizeof(virientry));
	virustypes[DET_BUILTIN].defcount++;
	lnode_create_prepend(viri[DET_BUILTIN], viridet);
	SecureServ.defcount ++;	
	dlog (DEBUG1, "loaded %s (Detection %d, with %s, send %s and do %d", viridet->name, viridet->dettype, viridet->recvmsg, viridet->sendmsg, viridet->action);
	
	for(i = 0; i < NUM_DAT_FILES; i++)
	{
		fp = os_fopen(DatFiles[i], "r");
		if (!fp) {
			if(i)
			{
				/* We do not really care if the custom file is not present so don't report it except in debug */
				/* as the comment says, we don't care about custom.dat, so don't fool users into thinking SecureSer is disabled by telling them it is! */
				dlog (DEBUG1, "No custom.dat file found.");
			}
			else
			{
				/* we *HAVE* to have a viri.dat file. Otherwise, no go */
				nlog (LOG_WARNING, "Error, No viri.dat file found.");
			}
			return;
		} else {
			re = pcre_compile("^([a-zA-Z0-9]*) ([0-9]*) ([0-9]*) ([0-9]*) \"(.*)\" \"(.*)\" ([0-9]*).*" , 0, &error, &errofset, NULL);
			if (re == NULL) {
				nlog (LOG_CRITICAL, "PCRE_COMPILE of dat file format failed bigtime! %s at %d", error, errofset);		
				return;
			}
			/* only set version for first file */
			if(i==0) 
			{
				/* first fgets always returns the version number */
				os_fgets(buf, BUFSIZE, fp);
				SecureServ.datfileversion = atoi(buf);
			}
			while (os_fgets(buf, BUFSIZE, fp)) {
				rc = pcre_exec(re, NULL, buf, strlen(buf), 0, 0, ovector, 24);
				if (rc <= 0) {
					nlog (LOG_WARNING, "PCRE_EXEC didn't have enough space! %d", rc);
					nlog (LOG_WARNING, "Load Was: %s", buf);
					continue;
				} else if (rc != 8) {
					nlog (LOG_WARNING, "Didn't get required number of Subs (%d)", rc);
					continue;
				}
				viridet = ns_calloc (sizeof(virientry));
				pcre_get_substring_list(buf, ovector, rc, &subs);		
				strlcpy(viridet->name, subs[1], MAXVIRNAME);
				viridet->dettype = atoi(subs[2]);
				if (viridet->dettype < 0 || viridet->dettype >= DET_MAX) {
					nlog (LOG_WARNING, "Unknown dettype %d for %s", viridet->dettype, viridet->name);
					ns_free (subs);
					ns_free (viridet);
					continue;
				}
				viridet->var1 = atoi(subs[3]);
				viridet->var2 = atoi(subs[4]);
				strlcpy(viridet->recvmsg, subs[5], BUFSIZE);
				strlcpy(viridet->sendmsg, subs[6], BUFSIZE);
				viridet->action = atoi(subs[7]);
				if (viridet->action < 0 || viridet->action >= ACT_MAX) {
					nlog (LOG_WARNING, "Unknown acttype %d for %s", viridet->action, viridet->name);
					ns_free (subs);
					ns_free (viridet);
					continue;
				}
				viridet->pattern = pcre_compile(viridet->recvmsg, 0, &error, &errofset, NULL);
				if (viridet->pattern == NULL) {
					/* it failed for some reason */
					nlog (LOG_WARNING, "Regular Expression Compile of %s Failed: %s at %d", viridet->name, error, errofset);
					ns_free (subs);
					ns_free (viridet);
					continue;
				}	
				viridet->iscustom=i;
				viridet->patternextra = pcre_study(viridet->pattern, 0, &error);
				if (error != NULL) {
					nlog (LOG_WARNING, "Regular Expression Study for %s failed: %s", viridet->name, error);
					/* don't exit */
				}
				virustypes[viridet->dettype].defcount++;
				lnode_create_prepend(viri[viridet->dettype], viridet);
				SecureServ.defcount ++;	
				dlog (DEBUG1, "loaded %s (Detection %d, with %s, send %s and do %d", viridet->name, viridet->dettype, viridet->recvmsg, viridet->sendmsg, viridet->action);
				ns_free (subs);
			}
			ns_free (re);
			os_fclose(fp);
		}
	}	
}

int ss_cmd_reload(const CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	irc_prefmsg (ss_bot, cmdparams->source, "Reloading virus definition files");
   	CommandReport(ss_bot, "Reloading virus definition files at request of %s", cmdparams->source->name);
	load_dat();
	return NS_SUCCESS;
}

int ss_cmd_list(const CmdParams *cmdparams) 
{
	lnode_t *node;
	virientry *ve;
	int i, count = 0;
	int fout = 0;

	SET_SEGV_LOCATION();
	irc_prefmsg (ss_bot, cmdparams->source, "Virus List:");
	irc_prefmsg (ss_bot, cmdparams->source, "===========");
	for(i = 0; i < DET_MAX; i++) {
		node = list_first(viri[i]);
		if (node) {
			fout = 1;
			irc_prefmsg (ss_bot, cmdparams->source, "Type %s", dettypes[i]);
			while (node) {
				ve = lnode_get(node);
				count++;
				irc_prefmsg (ss_bot, cmdparams->source, "%d) Virus: %s. Action: %s Hits: %d", count, ve->name, acttypes[ve->action], ve->numfound);
				node = list_next(viri[i], node);
			};
		}
	}
	if (fout) {
		irc_prefmsg (ss_bot, cmdparams->source, "End of list.");
	} else {
		irc_prefmsg (ss_bot, cmdparams->source, "No definitions found.");
	}
	return NS_SUCCESS;
}

int ScanFizzer(Client *u) 
{
	static char user[MAXREALNAME];
	static char username[10];
	lnode_t *node;
	virientry *viridetails;
	char *s1, *s2;

	SET_SEGV_LOCATION();
	strlcpy(user, u->info, MAXREALNAME); 
	s1 = strtok(user, " ");
	s2 = strtok(NULL, "");
	ircsnprintf(username, 10, "%s%s%s", u->user->username[0] == '~' ? "~" : "",  s2, s1);
#ifdef DEBUG
	dlog (DEBUG2, "Fizzer RealName Check %s -> %s", username, u->user->username);
#endif
	virustypes[DET_BUILTIN].trigcount++;
	if (!strcmp(username, u->user->username)) {
		nlog (LOG_NOTICE, "Fizzer Bot Detected: %s (%s -> %s)", u->name, u->user->username, u->info);
		/* do kill */
		node = list_first(viri[DET_BUILTIN]);
		if (node) {
			do {
				viridetails = lnode_get(node);
				if (ircstrcasecmp(viridetails->name, "FizzerBot")== 0 ) {
					gotpositive(u, viridetails, DET_BUILTIN);
					return 1;
				}
			} while ((node = list_next(viri[DET_BUILTIN], node)) != NULL);
		}
		return 1;
	}
	return 0;
}

static int Scan(int type, Client *u, char* buf) 
{
	int positive = 0;
	lnode_t *node;
	virientry *viridetails;
	int rc;

	SET_SEGV_LOCATION();
	node = list_first(viri[type]);
	if (node) {
		do {
			viridetails = lnode_get(node);
			virustypes[type].trigcount++;
#ifdef DEBUG
			dlog (DEBUG1, "Checking %s %s against %s", dettypes[type], buf, viridetails->recvmsg);
#endif
			rc = pcre_exec(viridetails->pattern, viridetails->patternextra, buf, strlen(buf), 0, 0, NULL, 0);
			if (rc < -1) {
				nlog (LOG_WARNING, "PatternMatch %s Failed: (%d)", dettypes[type], rc);
			} else if (rc > -1) {					
				nlog (LOG_NOTICE, "Got positive %s %s for %s against %s", dettypes[type], buf, viridetails->name, viridetails->recvmsg);
				gotpositive(u, viridetails, type);
				positive++;
				if (SecureServ.breakorcont != 0) {
					return 1;
				}
			}
		} while ((node = list_next(viri[type], node)) != NULL);
	}
	return positive;
}

int ScanNick(Client *u)
{
	return Scan(DET_NICK, u, u->name);
}

int ScanIdent(Client *u)
{
	return Scan(DET_IDENT, u, u->user->username);
}

int ScanRealname(Client *u)
{
	char *buf;
	unsigned int len;
	int i = 0;
		
	len = strlen( u->info );
	if( len == 0 )
		return 0;
	buf = ns_malloc( len );
	strlcpy( buf, u->info, len );
	strip_mirc_codes( buf );
	i = Scan(DET_REALNAME, u, buf);
	ns_free(buf);
	return i;
}

int ScanCTCPVersion(Client *u, char* buf) 
{
	strip_mirc_codes(buf);
	return Scan(DET_CTCP, u, buf);
}

int ScanPrivmsg(Client *u, char* buf) 
{
	strip_mirc_codes(buf);
	return Scan(DET_MSG, u, buf);
}

int ScanChanMsg(Client *u, char* buf) 
{
	strip_mirc_codes(buf);
	return Scan(DET_CHANMSG, u, buf);
}

int ScanChannelName(Client* u, Channel *c) 
{
	return Scan(DET_CHAN, u, c->name);
}

int ScanAwayMsg(Client* u, char* buf) 
{
	strip_mirc_codes(buf);
	return Scan(DET_AWAYMSG, u, buf);
}

int ScanQuitMsg(Client* u, char* buf) 
{
	if( buf )
	{
		strip_mirc_codes(buf);
		return Scan(DET_QUITMSG, u, buf);
	}
	return NS_SUCCESS;
}

int ScanTopic(Client* u, char* buf) 
{
	strip_mirc_codes(buf);
	return Scan(DET_TOPIC, u, buf);
}

static void report_positive (Client *u, virientry *ve)
{
	MMessage *msg;
	int32 *msgver;
	MByteBuffer **host;
	MByteBuffer **viri;
	int32 *datver;
	MByteBuffer **NeoVer;
	
	if (SecureServ.report == 1) {
		/* get our template message */
		msg = MQCreateMessage("SecureServ", "securebot", 0, NULL, 1);
		if (msg) {
			msgver = MMPutInt32Field(msg, false, "msgver", 1);
			host = MMPutStringField(msg, false, "Host", 1);
			viri = MMPutStringField(msg, false, "Viri", 1);
			NeoVer = MMPutStringField(msg, false, "NeoVer", 1);
			datver = MMPutInt32Field(msg, false, "Dat", 1);
			host[0] = MBStrdupByteBuffer(u->hostip);
			viri[0] = MBStrdupByteBuffer(ve->name);
			NeoVer[0] = MBStrdupByteBuffer(MODULE_VERSION);
			datver[0] = SecureServ.datfileversion;
			/* msgver 1 = SecureServ, msgver 2 = OPSB */
			msgver[0] = 1;
			MQSendMessage(msg, 1);
		} else {
			nlog(LOG_WARNING, "Couldn't create Report Message");
		}
	}	
}

void gotpositive(Client *u, virientry *ve, int type) 
{
	UserDetail *ud;

	SET_SEGV_LOCATION();
	if (!u) /* User not found */
		return;
	/* Initial message is based on an assumption that the action determines the threat level */
	switch(ve->action) {
		case ACT_SVSJOIN:
			irc_prefmsg (ss_bot, u, "%s has detected that your client is an infected IRC client called %s", ss_bot->name, ve->name);
			break;
		case ACT_AKILL:
			irc_prefmsg (ss_bot, u, "%s has detected that your client is a Trojan or War Script called %s", ss_bot->name, ve->name);
			break;
		case ACT_KILL:
			irc_prefmsg (ss_bot, u, "%s has detected that your client is a Trojan or War Script called %s", ss_bot->name, ve->name);
			break;
		case ACT_WARN:
			irc_prefmsg (ss_bot, u, "%s has detected that you or your client is sending unsolicted messages to other users", ss_bot->name);
			break;
		case ACT_NOTHING:
			irc_prefmsg (ss_bot, u, "%s has detected that your client is a vulnerable script or client called %s", ss_bot->name, ve->name);
			break;
		default:
			break;
	} 		
	irc_prefmsg (ss_bot, u, ve->sendmsg);
	/* Do not generate a URL for local custom definitions since it will not exist*/
	if(!ve->iscustom)
		irc_prefmsg (ss_bot, u, "For More Information Please Visit http://secure.irc-chat.net/info.php?viri=%s", ve->name);
	ve->numfound++;
	virustypes[type].actcount++;
	/* by default, dont do any action to opers, but report it */
	
	if (IsOper(u)) {
		if(ve->iscustom) {
			irc_globops (ss_bot, "Warning, Operator %s is Infected with %s Trojan/Virus. No Action Taken ", u->name, ve->name);
		} else {
			irc_globops (ss_bot, "Warning, Operator %s is Infected with %s Trojan/Virus. No Action Taken (See http://secure.irc-chat.net/info.php?viri=%s for more info)", u->name, ve->name, ve->name);
		}
		nlog (LOG_NOTICE, "Operator %s!%s@%s has Virus %s", u->name, u->user->username, u->user->hostname, ve->name);
		report_positive (u, ve);
		return;
	}	
	switch (ve->action) {
		case ACT_SVSJOIN:
			if (SecureServ.dosvsjoin > 0) {
				if (SecureServ.helpcount > 0) {		
					ud = ns_malloc (sizeof(UserDetail));
					ud->type = USER_INFECTED;
					ud->data = (void *)ve;
					SetUserModValue (u, (void *)ud);
					irc_chanalert (ss_bot, "SVSJoining %s to %s for Virus %s", u->name, SecureServ.HelpChan, ve->name);
					if(ve->iscustom) {
						irc_globops (ss_bot, "SVSJoining %s for Virus %s", u->name, ve->name);
					} else {
						irc_globops (ss_bot, "SVSJoining %s for Virus %s (http://secure.irc-chat.net/info.php?viri=%s)", u->name, ve->name, ve->name);
					}
					if (!IsChannelMember(FindChannel(SecureServ.HelpChan), u)) {
						irc_svsjoin (ss_bot, u, SecureServ.HelpChan);
					}
					nlog (LOG_NOTICE, "SVSJoining %s to %s for Virus %s", u->name, SecureServ.HelpChan, ve->name);
					if(ve->iscustom) {
						irc_chanprivmsg (ss_bot, SecureServ.HelpChan, "%s is infected with %s.", u->name, ve->name);
					} else {
						irc_chanprivmsg (ss_bot, SecureServ.HelpChan, "%s is infected with %s. More information at http://secure.irc-chat.net/info.php?viri=%s", u->name, ve->name, ve->name);
					}
					break;
				} else {
					irc_prefmsg (ss_bot, u, "%s", SecureServ.nohelp);
					irc_chanalert (ss_bot, "Akilling %s!%s@%s for Virus %s (No Helpers Logged in)", u->name, u->user->username, u->user->hostname, ve->name);
					if(ve->iscustom) {
						irc_globops (ss_bot, "Akilling %s for Virus %s (No Helpers Logged in)", u->name, ve->name);
					}
					else {
						irc_globops (ss_bot, "Akilling %s for Virus %s (No Helpers Logged in) (http://secure.irc-chat.net/info.php?viri=%s)", u->name, ve->name, ve->name);
					}
					irc_akill (ss_bot, u->user->hostname, u->user->username, SecureServ.akilltime, "SecureServ(SVSJOIN): %s", ve->name);
					nlog (LOG_NOTICE, "Akilling %s!%s@%s for Virus %s (No Helpers Logged in)", u->name, u->user->username, u->user->hostname, ve->name);
					break;
				}
			}
			/* fallthrough */
		case ACT_AKILL:
			if (SecureServ.doakill > 0) {
				irc_prefmsg (ss_bot, u, SecureServ.akillinfo);
				irc_chanalert (ss_bot, "Akilling %s!%s@%s for Virus %s", u->name, u->user->username, u->user->hostname, ve->name);
				if(ve->iscustom) {
					irc_akill (ss_bot, u->user->hostname, "*", SecureServ.akilltime, "Infected with: %s ", ve->name);
				} else {
					irc_akill (ss_bot, u->user->hostname, "*", SecureServ.akilltime, "Infected with: %s (See http://secure.irc-chat.net/info.php?viri=%s for more info)", ve->name, ve->name);
				}
				nlog (LOG_NOTICE, "Akilling %s!%s@%s for Virus %s", u->name, u->user->username, u->user->hostname, ve->name);
				break;
			}
			/* fallthrough */
		case ACT_KILL:
			irc_prefmsg (ss_bot, u, "%s", SecureServ.akillinfo);
			irc_chanalert (ss_bot, "Killing %s!%s@%s for Virus %s", u->name, u->user->username, u->user->hostname, ve->name);
			if(ve->iscustom) {
				irc_kill (ss_bot, u->name, "Infected with: %s ", ve->name);
			} else {
				irc_kill (ss_bot, u->name, "Infected with: %s (See http://secure.irc-chat.net/info.php?viri=%s for more info)", ve->name, ve->name);
			}
			nlog (LOG_NOTICE, "Killing %s!%s@%s for Virus %s", u->name, u->user->username, u->user->hostname, ve->name);
			break;
		case ACT_WARN:
			irc_chanalert (ss_bot, "Warning, %s is Infected with %s Trojan/Virus. No Action Taken", u->name, ve->name);
			if(ve->iscustom) {
				irc_globops (ss_bot, "Warning, %s is Infected with %s Trojan/Virus. No Action Taken ", u->name, ve->name);
			} else {
				irc_globops (ss_bot, "Warning, %s is Infected with %s Trojan/Virus. No Action Taken (See http://secure.irc-chat.net/info.php?viri=%s for more info)", u->name, ve->name, ve->name);
			}
			if (SecureServ.helpcount > 0) {
				if(ve->iscustom) {
					irc_chanprivmsg (ss_bot, SecureServ.HelpChan, "%s is infected with %s.", u->name, ve->name);
				} else {
					irc_chanprivmsg (ss_bot, SecureServ.HelpChan, "%s is infected with %s. More information at http://secure.irc-chat.net/info.php?viri=%s", u->name, ve->name, ve->name);
				}
			}
			nlog (LOG_NOTICE, "Warning, %s is Infected with %s Trojan/Virus. No Action Taken ", u->name, ve->name);
			break;
		case ACT_NOTHING:
			if (SecureServ.verbose) irc_chanalert (ss_bot, "Warned %s about %s Bot/Trojan/Virus", u->name, ve->name);
			nlog (LOG_NOTICE, "Warned %s about %s Bot/Trojan/Virus", u->name, ve->name);
			break;
		default:
			break;
	}
	report_positive (u, ve);
}
