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
** $Id: SecureServ.h 414 2007-07-30 10:49:09Z DNB $
*/

#ifndef SECURESERV_H
#define SECURESERV_H

#include "neostats.h"
#include MODULECONFIG

#define VIRI_DAT_NAME		"data/viri.dat"
#define CUSTOM_DAT_NAME		"data/customviri.dat"
#define NUM_DAT_FILES	2

#define MAXVIRNAME		64
#define MAXCTCPTYPE		64

typedef struct virientry {
	char name[MAXVIRNAME];
	int dettype;
	int var1;
	int var2;
	char ctcptype[MAXCTCPTYPE];
	char recvmsg[BUFSIZE];
	pcre *pattern;
	pcre_extra *patternextra;
	char sendmsg[BUFSIZE];
	int action;
	int numfound;
	int iscustom;
} virientry;

/* Detection Types */
typedef enum DET_TYPE {
	DET_CTCP = 0,
	DET_MSG,
	DET_NICK,
	DET_IDENT,
	DET_REALNAME,
	DET_CHAN,
	DET_CHANMSG,
	DET_AWAYMSG,
	DET_QUITMSG,
	DET_TOPIC,
	DET_BUILTIN,
	DET_MAX
} DET_TYPE;

/* Action List */
typedef enum ACT_TYPE {
	ACT_SVSJOIN = 0,
	ACT_AKILL,
	ACT_WARN,
	ACT_NOTHING,
	ACT_KILL,
	ACT_MAX
} ACT_TYPE;

extern Bot *ss_bot;

typedef struct UserDetail {
	int type;
	void *data;
} UserDetail;

/* type list */
#define USER_HELPER 1
#define USER_INFECTED 2


#define SS_BUF_SIZE 255
#define MAX_PATTERN_TYPES	20

typedef struct SecureServcfg {
	int version;
	int datfileversion;
	char akillinfo[BUFSIZE];
	char nohelp[BUFSIZE];
	char HelpChan[MAXCHANLEN];
	int breakorcont;
	int doakill;
	int akilltime;
	int dosvsjoin;
	int helpcount;
	int verbose;
	int stayinchantime;
	int monchancycletime;
	int autoupgrade;
	int autoupgradetime;
	int dofizzer;
	int DoOnJoin;
	int BotEcho;
	int helpers;
	int defcount;
	char monbot[MAXNICK];
	char botquitmsg[BUFSIZE];
	int doprivchan;
	int signoutaway;
	int report;
	int joinhelpchan;
	char sampleversion[SS_BUF_SIZE];
	int monchancycle;
#ifdef TREATCHANMSGASPM
	int treatchanmsgaspm;
#endif /* TREATCHANMSGASPM */ 
	int exclusions;
} SecureServcfg;

#define SS_IS_CHANNEL_EXCLUDED( c ) ( ModIsChannelExcluded( c ) || ( SecureServ.exclusions && IsExcluded( c ) ) )

extern SecureServcfg SecureServ;

/* SecureServ.c */

/* update.c */
int ss_cmd_update(const CmdParams *cmdparams);
int ss_cmd_set_autoupdate_cb (const CmdParams *cmdparams, SET_REASON reason);
int ss_cmd_set_autoupdatetime_cb (const CmdParams *cmdparams, SET_REASON reason);
int AutoUpdate(void *);

/* OnJoin.c */
int JoinNewChan(void *);
void OnJoinBotStatus (const CmdParams *cmdparams);
int ss_event_message (const CmdParams *cmdparams);
int ss_event_versionrequest (const CmdParams *cmdparams);
int LoadMonChans();
int InitOnJoinBots(void);
void FiniOnJoinBots(void);
int ss_cmd_bots(const CmdParams *cmdparams);
int ss_cmd_checkchan(const CmdParams *cmdparams);
int ss_cmd_monchan(const CmdParams *cmdparams);
int ss_cmd_cycle(const CmdParams *cmdparams);
int ss_cmd_set_monbot (const CmdParams *cmdparams, SET_REASON reason);
int ss_event_kickbot(const CmdParams *cmdparams);
int ss_event_emptychan(const CmdParams *cmdparams);
int MonJoin(const Channel *c);
int CheckMonBotKill(const CmdParams *cmdparams);
int CheckOnJoinBotKill(const CmdParams *cmdparams);
int MonBotCycle(void *);

/* scan.c */
void ScanStatus (const CmdParams *cmdparams);
int ScanFizzer(Client *u);
int ScanChannelName(Client* u, Channel *c);
int ScanNick(Client *u);
int ScanIdent(Client *u);
int ScanRealname(Client *u);
int ScanPrivmsg(Client *u, char* buf);
int ScanChanMsg(Client *u, char* buf);
int ScanCTCPVersion(Client *u, char* buf);
int ScanAwayMsg(Client* u, char* buf);
int ScanQuitMsg(Client* u, char* buf); 
int ScanTopic(Client* u, char* buf);

int ss_cmd_list(const CmdParams *cmdparams);
int ss_cmd_reload(const CmdParams *cmdparams);
void InitScanner(void);
void load_dat(void);

/* Helpers.c */
int InitHelpers(void);
void FiniHelpers(void);
int HelpersSignoff(Client *c);
int HelpersAway(const CmdParams *cmdparams);
void HelpersStatus (const CmdParams *cmdparams);
int ss_cmd_set_helpers_cb(const CmdParams *cmdparams, SET_REASON reason);

/* SecureServ_help.c */
extern const char *ts_help_checkchan[];
extern const char *ts_help_login[];
extern const char *ts_help_logout[];
extern const char *ts_help_chpass[];
extern const char *ts_help_cycle[];
extern const char *ts_help_update[];
extern const char *ts_help_status[];
extern const char *ts_help_list[];
extern const char *ts_help_bots[];
extern const char *ts_help_monchan[];
extern const char *ts_help_assist[];
extern const char *ts_help_helpers[];
extern const char *ts_help_reload[];

extern const char *ts_help_set_version[];
extern const char *ts_help_set_helpers[];
extern const char *ts_help_set_signonmsg[];
extern const char *ts_help_set_botquitmsg[];
extern const char *ts_help_set_akillmsg[];
extern const char *ts_help_set_nohelpmsg[];
extern const char *ts_help_set_helpchan[];
extern const char *ts_help_set_autosignout[];
extern const char *ts_help_set_joinhelpchan[];
extern const char *ts_help_set_report[];
extern const char *ts_help_set_doprivchan[];
extern const char *ts_help_set_checkfizzer[];
extern const char *ts_help_set_multicheck[];
extern const char *ts_help_set_akill[];
extern const char *ts_help_set_akilltime[];
extern const char *ts_help_set_dojoin[];
extern const char *ts_help_set_doonjoin[];
extern const char *ts_help_set_botecho[];
extern const char *ts_help_set_verbose[];
extern const char *ts_help_set_monchancycle[];
#ifdef TREATCHANMSGASPM
extern const char *ts_help_set_treatchanmsgaspm[];
#endif /* TREATCHANMSGASPM */ 
extern const char *ts_help_set_monchancycletime[];
extern const char *ts_help_set_cycletime[];
extern const char *ts_help_set_monbot[];
extern const char *ts_help_set_autoupdate[];
extern const char *ts_help_set_autoupdatetime[];
extern const char *ts_help_set_updateuser[];
extern const char *ts_help_set_updatepass[];
extern const char *ts_help_set_onjoinbotmodes[];
extern const char *ts_help_set_exclusions[];

extern char onjoinbot_modes[MODESIZE];

#endif /* SECURESERV_H */
