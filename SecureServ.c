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
** $Id: SecureServ.c 414 2007-07-30 10:49:09Z DNB $
*/

#include "SecureServ.h"
#include "updates.h"

static int ss_event_signon( const CmdParams *cmdparams );
static int ss_event_versionreply( const CmdParams *cmdparams );
static int ss_event_nick( const CmdParams *cmdparams );
static int ss_event_quit( const CmdParams *cmdparams );
static int ss_event_kill( const CmdParams *cmdparams );
static int ss_cmd_status( const CmdParams *cmdparams );
static int ss_cmd_viriversion( const CmdParams *cmdparams );

static int ss_cmd_set_doonjoin_cb( const CmdParams *cmdparams, SET_REASON reason );
static int ss_cmd_set_monchancycle_cb( const CmdParams *cmdparams, SET_REASON reason );
static int ss_cmd_set_monchancycletime_cb( const CmdParams *cmdparams, SET_REASON reason );
static int ss_cmd_set_cycletime_cb( const CmdParams *cmdparams, SET_REASON reason );
static int ss_set_exclusions_cb( const CmdParams *cmdparams, SET_REASON reason );

#ifdef WIN32
static void *(*old_malloc)(size_t);
static void (*old_free) (void *);
#endif

Bot *ss_bot;
SecureServcfg SecureServ;

/** about info */
static const char *ss_about[] = {
	"A Trojan Scanning Bot",
	NULL
};

static const char *ss_copyright[] = {
	"Copyright (c) 1999-2005, NeoStats",
	"http://www.neostats.net/",
	NULL
};

/** Module Info definition 
 * version information about our module
 * This structure is required for your module to load and run on NeoStats
 */
ModuleInfo module_info = {
	"SecureServ",
	"A Trojan Scanning Bot",
	ss_copyright,
	ss_about,
	NEOSTATS_VERSION,
	MODULE_VERSION,
	__DATE__,
	__TIME__,
	MODULE_FLAG_CTCP_VERSION | MODULE_FLAG_LOCAL_EXCLUDES,
	0,
	0,
};

static bot_cmd ss_commands[]=
{
	{"LIST",	ss_cmd_list,		0,	NS_ULEVEL_OPER, ts_help_list, 0, NULL, NULL},
	{"CHECKCHAN",ss_cmd_checkchan,	1,	NS_ULEVEL_OPER, ts_help_checkchan, 0, NULL, NULL},
	{"CYCLE",	ss_cmd_cycle,		0,	NS_ULEVEL_OPER, ts_help_cycle, 0, NULL, NULL},
	{"UPDATE",	ss_cmd_update,		0,	NS_ULEVEL_ADMIN,ts_help_update, 0, NULL, NULL},
	{"STATUS",	ss_cmd_status,		0,	NS_ULEVEL_OPER, ts_help_status, 0, NULL, NULL},
	{"BOTS",	ss_cmd_bots,		1,	100,			ts_help_bots, 0, NULL, NULL},
	{"MONCHAN",	ss_cmd_monchan,		1,	NS_ULEVEL_OPER, ts_help_monchan, 0, NULL, NULL},
	{"RELOAD",	ss_cmd_reload,		0,	NS_ULEVEL_OPER, ts_help_reload, 0, NULL, NULL},
	{"VERSION",	ss_cmd_viriversion,	0,	0,				NULL, 0, NULL, NULL},
	NS_CMD_END()
};

static bot_setting ss_settings[]=
{
	{"HELPERS",		&SecureServ.helpers,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,NULL,	ts_help_set_helpers, ss_cmd_set_helpers_cb, (void *)1 },
	{"VERSION",		&SecureServ.version,		SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,NULL,	ts_help_set_version, NULL, (void *)1 },
	{"HELPCHAN",	SecureServ.HelpChan,	SET_TYPE_CHANNEL,	0,	MAXCHANLEN,	NS_ULEVEL_ADMIN,NULL,	ts_help_set_helpchan, NULL, (void *)"#nohack" },
	{"REPORT",		&SecureServ.report,		SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,NULL,	ts_help_set_report, NULL, (void *)1 },
	{"DOPRIVCHAN",	&SecureServ.doprivchan,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,NULL,	ts_help_set_doprivchan, NULL, (void *)1 },
	{"CHECKFIZZER",	&SecureServ.dofizzer,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,NULL,	ts_help_set_checkfizzer, NULL, (void *)1 },
	{"MULTICHECK",	&SecureServ.breakorcont,SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,NULL,	ts_help_set_multicheck, NULL, (void *)1 },
	{"AKILL",		&SecureServ.doakill,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,NULL,	ts_help_set_akill, NULL, (void *)1 },
	{"AKILLTIME",	&SecureServ.akilltime,	SET_TYPE_INT,		0,	20736000,	NS_ULEVEL_ADMIN,NULL,	ts_help_set_akilltime, NULL, (void *)TS_ONE_HOUR },
	{"AKILLMSG",	SecureServ.akillinfo,	SET_TYPE_MSG,		0,	BUFSIZE,	NS_ULEVEL_ADMIN,NULL,	ts_help_set_akillmsg, NULL, (void *)"You have been Akilled from this network. Please get a virus scanner and check your PC" },
	{"SVSJOIN",		&SecureServ.dosvsjoin,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,NULL,	ts_help_set_dojoin, NULL, (void *)1 },
#ifdef TREATCHANMSGASPM
	{"TREATCHANMSGASPM", &SecureServ.treatchanmsgaspm,SET_TYPE_BOOLEAN,0,0,		NS_ULEVEL_ADMIN,NULL,	ts_help_set_treatchanmsgaspm, NULL, (void *)0 },
#endif /* TREATCHANMSGASPM */ 
	{"DOONJOIN",	&SecureServ.DoOnJoin,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,NULL,	ts_help_set_doonjoin, ss_cmd_set_doonjoin_cb, (void *)1 },
	{"VERBOSE",		&SecureServ.verbose,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,NULL,	ts_help_set_verbose, NULL, (void *)1 },
	{"BOTECHO",		&SecureServ.BotEcho,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,NULL,	ts_help_set_botecho, NULL, (void *)0 },
	{"BOTQUITMSG",	SecureServ.botquitmsg,	SET_TYPE_MSG,		0,	BUFSIZE,	NS_ULEVEL_ADMIN,NULL,	ts_help_set_botquitmsg, NULL, (void *)"Client quit" },
	{"MONCHANCYCLE",&SecureServ.monchancycle,SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,NULL,	ts_help_set_monchancycle, ss_cmd_set_monchancycle_cb, (void *)1 },
	{"MONCHANCYCLETIME", &SecureServ.monchancycletime,SET_TYPE_INT, 1,	100000,		NS_ULEVEL_ADMIN,NULL,	ts_help_set_monchancycletime, ss_cmd_set_monchancycletime_cb, (void *)1800 },
	{"CYCLETIME",	&SecureServ.stayinchantime,SET_TYPE_INT,	1,	100000,		NS_ULEVEL_ADMIN,NULL,	ts_help_set_cycletime, ss_cmd_set_cycletime_cb, (void *)TS_ONE_MINUTE },
	{"MONBOT",		NULL,					SET_TYPE_CUSTOM,	0,	0,			NS_ULEVEL_ADMIN,NULL,	ts_help_set_monbot, ss_cmd_set_monbot, (void *)0 },
	{"AUTOUPDATE",	&SecureServ.autoupgrade,SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,NULL,	ts_help_set_autoupdate, ss_cmd_set_autoupdate_cb, (void *)0 },
	{"AUTOUPDATETIME",	&SecureServ.autoupgradetime,SET_TYPE_INT,	TS_ONE_HOUR,	172800,			NS_ULEVEL_ADMIN,NULL,	ts_help_set_autoupdatetime, ss_cmd_set_autoupdatetime_cb, (void *)7200 },
	{"ONJOINBOTMODES",onjoinbot_modes,		SET_TYPE_STRING,	0,	MODESIZE,	NS_ULEVEL_ADMIN,NULL,	ts_help_set_onjoinbotmodes, NULL, (void *)"+" },
	{"EXCLUSIONS",	&SecureServ.exclusions,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,NULL,	ts_help_set_exclusions, ss_set_exclusions_cb, (void *)0 },
	NS_SETTING_END()
};

static BotInfo ss_botinfo =
{
	"SecureServ",
	"SecureServ1",
	"TS",
	BOT_COMMON_HOST, 
	"Trojan Scanning Bot",
	BOT_FLAG_SERVICEBOT|BOT_FLAG_DEAF|BOT_FLAG_CTCPVERSIONMASTER, 
	ss_commands, 
	ss_settings,
};

static int ss_cmd_set_doonjoin_cb(const CmdParams *cmdparams, SET_REASON reason)
{
	if( reason == SET_CHANGE )
	{
		if( SecureServ.DoOnJoin )
		{
			AddTimer( TIMER_TYPE_INTERVAL, JoinNewChan, "JoinNewChan", SecureServ.stayinchantime, NULL );
		}
		else
		{
			DelTimer( "JoinNewChan" );
		}
	}
	return NS_SUCCESS;
}
static int ss_cmd_set_monchancycle_cb(const CmdParams *cmdparams, SET_REASON reason)
{
	if( reason == SET_CHANGE )
	{
		if( SecureServ.monchancycle )
		{
			AddTimer( TIMER_TYPE_INTERVAL, MonBotCycle, "MonBotCycle", SecureServ.monchancycletime, NULL );
		}
		else
		{
			DelTimer( "MonBotCycle" );
		}
	}
	return NS_SUCCESS;
}
static int ss_cmd_set_monchancycletime_cb(const CmdParams *cmdparams, SET_REASON reason)
{
	if( reason == SET_CHANGE )
	{
		SetTimerInterval ("MonBotCycle", SecureServ.monchancycletime);
	}
	return NS_SUCCESS;
}
static int ss_cmd_set_cycletime_cb(const CmdParams *cmdparams, SET_REASON reason)
{
	if( reason == SET_CHANGE )
	{
		SetTimerInterval ("JoinNewChan", SecureServ.stayinchantime);
	}
	return NS_SUCCESS;
}

static int ss_set_exclusions_cb( const CmdParams *cmdparams, SET_REASON reason )
{
	if( reason == SET_LOAD || reason == SET_CHANGE )
	{
		SetAllEventFlags( EVENT_FLAG_USE_EXCLUDE, SecureServ.exclusions );
	}
	return NS_SUCCESS;
}

static int ss_cmd_viriversion(const CmdParams *cmdparams)
{
	irc_prefmsg (ss_bot, cmdparams->source, "%d", SecureServ.datfileversion);
	return NS_SUCCESS;
}

static int ss_cmd_status(const CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	irc_prefmsg (ss_bot, cmdparams->source, "SecureServ Status:");
	irc_prefmsg (ss_bot, cmdparams->source, "==================");
	ScanStatus (cmdparams);
	HelpersStatus (cmdparams);
	OnJoinBotStatus (cmdparams);
	irc_prefmsg (ss_bot, cmdparams->source, "End of list.");
	return NS_SUCCESS;
}

static int ss_event_newchan( const CmdParams *cmdparams )
{
	SET_SEGV_LOCATION();
	SetChannelModValue(cmdparams->channel, (void *) 0 );
	/* check if its a monchan and we are not in place */
	MonJoin( cmdparams->channel );
	return NS_SUCCESS;
}

static int ss_event_joinchan(const CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	/* is channel exempt? */
	if( SS_IS_CHANNEL_EXCLUDED( cmdparams->channel ) )
		return NS_SUCCESS;
	/* is user exempt */
	if( ModIsUserExcluded( cmdparams->source ) == NS_TRUE )
		return NS_SUCCESS;
	/* is channel already scanned */
	if( GetChannelModValue( cmdparams->channel ) == 0 ) {
		/* only set the channel to scanned if clean so defintion remains active */
		if( ScanChannelName( cmdparams->source, cmdparams->channel ) == 0 )
			SetChannelModValue( cmdparams->channel, ( void * ) 1 );
	}
	return NS_SUCCESS;
}

static int ss_event_delchan(const CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	ClearChannelModValue (cmdparams->channel);
	return NS_SUCCESS;
}

static int ss_event_away(const CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	HelpersAway(cmdparams);
	ScanAwayMsg(cmdparams->source, cmdparams->source->user->awaymsg);
	return NS_SUCCESS;
}

static int ss_event_topic(const CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	ScanTopic(cmdparams->source, cmdparams->channel->topic);
	return NS_SUCCESS;
}

static int ss_event_channelmessage (const CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	/* first, if its the services channel, just ignore it */
	if (IsServicesChannel( cmdparams->channel )) {
		return NS_SUCCESS;
	}
	if (ModIsUserExcluded(cmdparams->source) == NS_TRUE) {
		dlog (DEBUG1, "User %s is exempt from Message Checking", cmdparams->source->name);
		return NS_SUCCESS;
	}
	ScanChanMsg(cmdparams->source, cmdparams->param);
#ifdef TREATCHANMSGASPM
	if (SecureServ.treatchanmsgaspm == 1) {
		ScanPrivmsg(cmdparams->source, cmdparams->param);
	}
#endif /* TREATCHANMSGASPM */ 
	return NS_SUCCESS;
}

static int ss_event_botkill(const CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	/* Check the mon bot first */
	if(CheckMonBotKill(cmdparams)==NS_TRUE) {
		return NS_SUCCESS;
	}
	/* What else should we check? */
	/* Check the on join bot as well */
	if(CheckOnJoinBotKill(cmdparams)==NS_TRUE) {
		return NS_SUCCESS;
	}
	return NS_SUCCESS;
}

ModuleEvent module_events[] = {
	{ EVENT_SIGNON, 		ss_event_signon, 0},
	{ EVENT_QUIT, 			ss_event_quit,		EVENT_FLAG_EXCLUDE_ME},
	{ EVENT_KILL, 			ss_event_quit, 0},
	{ EVENT_JOIN, 			ss_event_joinchan,	EVENT_FLAG_EXCLUDE_MODME},
	{ EVENT_DELCHAN,		ss_event_delchan, 0},
	{ EVENT_NICK,			ss_event_nick, 0},
	{ EVENT_EMPTYCHAN,		ss_event_emptychan, 0},	
	{ EVENT_KICKBOT,		ss_event_kickbot, 0},
	{ EVENT_AWAY, 			ss_event_away, 0},
	{ EVENT_TOPIC, 			ss_event_topic, 0},
	{ EVENT_NEWCHAN,		ss_event_newchan, 0},
	{ EVENT_PRIVATE, 		ss_event_message, 0},
	{ EVENT_NOTICE, 		ss_event_message, 0},
	{ EVENT_CPRIVATE, 		ss_event_channelmessage, 0},
	{ EVENT_CNOTICE, 		ss_event_channelmessage, 0},
	{ EVENT_BOTKILL, 		ss_event_botkill, 0},
	{ EVENT_CTCPVERSIONRPLBC, ss_event_versionreply, 0},	
	{ EVENT_CTCPVERSIONREQ, ss_event_versionrequest, 0},	
	NS_EVENT_END()
};

static int ss_event_quit(const CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	HelpersSignoff(cmdparams->source);
	ScanQuitMsg(cmdparams->source, cmdparams->param); 
	return NS_SUCCESS;
}

static int ss_event_kill(const CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	HelpersSignoff(cmdparams->target);
	ScanQuitMsg(cmdparams->target, cmdparams->param); 
	return NS_SUCCESS;
}

/* scan nickname changes */
static int ss_event_nick(const CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	if (ModIsUserExcluded(cmdparams->source) == NS_FALSE) {
		/* check the nickname */
		ScanNick(cmdparams->source);
	}
	return NS_SUCCESS;
}

/* scan someone connecting */
static int ss_event_signon(const CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	if (IsNetSplit(cmdparams->source)) {
		dlog (DEBUG1, "Ignoring netsplit nick %s", cmdparams->source->name);
		return NS_SUCCESS;
	}
	if (ModIsUserExcluded(cmdparams->source) == NS_TRUE)
		return NS_SUCCESS;
	/* fizzer scan */
	if (SecureServ.dofizzer && ScanFizzer(cmdparams->source))
		return NS_SUCCESS;
	/* check the nickname, ident, realname */
	if (ScanNick(cmdparams->source) && SecureServ.breakorcont != 0)
		return NS_SUCCESS;
	if (ScanIdent(cmdparams->source) && SecureServ.breakorcont != 0)
		return NS_SUCCESS;
	if (ScanRealname(cmdparams->source) && SecureServ.breakorcont != 0)
		return NS_SUCCESS;
	return NS_SUCCESS;
}

static int ss_event_versionreply(const CmdParams *cmdparams) 
{
	int positive = 0;
	static int versioncount = 0;

	SET_SEGV_LOCATION();
	if( !SecureServ.version )
		return NS_SUCCESS;
	/* because neostats doesn't check this when the version request comes from the core */
	if( IsNetSplit( cmdparams->source ) )
	{
		dlog (DEBUG1, "Ignoring netsplit nick %s", cmdparams->source->name);
		return NS_SUCCESS;
	}
	if (ModIsUserExcluded(cmdparams->source) == NS_TRUE)
		return NS_SUCCESS;
	if (SecureServ.verbose) 
		irc_chanalert(ss_bot, "Got Version Reply from %s: %s", cmdparams->source->name, cmdparams->param);
	positive = ScanCTCPVersion(cmdparams->source, cmdparams->param);
	versioncount++;
	/* why do we only change the version reply every 23 entries? Why not? */
	if ((positive == 0) && (versioncount > 23))
	{
		strlcpy(SecureServ.sampleversion, cmdparams->param, SS_BUF_SIZE);
		versioncount = 0;
	}
	return NS_SUCCESS;
}

/** Init module
 */

int ModInit( void )
{
	SET_SEGV_LOCATION();
#ifdef WIN32
	old_malloc = pcre_malloc;
	old_free = pcre_free;
	pcre_malloc = os_malloc;
	pcre_free = os_free;
#endif
	os_memset (&SecureServ, 0, sizeof (SecureServ));
	ModuleConfig (ss_settings);
	InitScanner();
	InitOnJoinBots();
	return NS_SUCCESS;
}

static int ScanMember( Channel *c, ChannelMember *m, void *v )
{
	if( ModIsUserExcluded( m->u ) == NS_FALSE ) {
		if( ScanChannelName( m->u, c ) == 0 ) {
			/* Channel is OK so mark as clean */
			SetChannelModValue( c, (void *) 1 );
			return NS_TRUE;
		}
	}
	return NS_FALSE;
}

static int ScanChannel (Channel *c, void *v)
{
	ProcessChannelMembers( c, ScanMember, NULL );
	return NS_FALSE;
}

/** @brief ModSynch
 *
 *  Startup handler
 *
 *  @param none
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

int ModSynch( void )
{
	SET_SEGV_LOCATION();
	ss_bot = AddBot( &ss_botinfo );
	if( !ss_bot )
		return NS_FAILURE;
	if( InitHelpers() == NS_FAILURE )
		return NS_FAILURE;
	if( SecureServ.verbose )
		irc_chanalert( ss_bot, "%d definitions loaded", SecureServ.defcount );
	srand( NSGetChannelCount() );
	/* kick of the autojoin timer */
	if( SecureServ.DoOnJoin )
		AddTimer( TIMER_TYPE_INTERVAL, JoinNewChan, "JoinNewChan", SecureServ.stayinchantime, NULL );
	if( SecureServ.monchancycle )
		AddTimer( TIMER_TYPE_INTERVAL, MonBotCycle, "MonBotCycle", SecureServ.monchancycletime, NULL );

	if (MQCredOk() == NS_SUCCESS) {
		AutoUpdate( NULL );
		AddTimer( TIMER_TYPE_INTERVAL, AutoUpdate, "AutoUpdate", SecureServ.autoupgradetime, NULL );
	} else if (SecureServ.autoupgrade == 1) {
		irc_chanalert (ss_bot, "No valid NeoNet Account configured for SecureServ Dat File Update");
	}
	LoadMonChans();
	ProcessChannelList( ScanChannel, NULL );
	return NS_SUCCESS;
}

/** Fini module
 * This is required if you need to do cleanup of your module when it ends
 */
int ModFini( void )
{
	SET_SEGV_LOCATION();
	FiniHelpers();
	FiniOnJoinBots();
#ifdef WIN32
	pcre_malloc = old_malloc;
	pcre_free = old_free;
#endif
	return NS_SUCCESS;
}

int ModAuthUser( const Client *u )
{
	UserDetail *ud;

	ud = ( UserDetail * )GetUserModValue( u );
	if( ud && ud->type == USER_HELPER )
		return 30;
	return 0;
}
