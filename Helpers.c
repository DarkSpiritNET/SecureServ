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
** $Id: Helpers.c 413 2007-07-27 17:43:57Z DNB $
*/

#include "SecureServ.h"

/** Helper list struct */

typedef struct Helper
{
	char nick[MAXNICK];
	char pass[MAXNICK];
	Client *u;
} Helper;

/** hash for storing helper list */
static hash_t *helperhash;

/* Command prototypes */
static int ss_cmd_login( const CmdParams *cmdparams );
static int ss_cmd_logout( const CmdParams *cmdparams );
static int ss_cmd_assist( const CmdParams *cmdparams );
static int ss_cmd_helpers( const CmdParams *cmdparams );
static int ss_cmd_chpass( const CmdParams *cmdparams );

/** helper command list */
static bot_cmd helper_commands[]=
{
	{"LOGIN",	ss_cmd_login,	2,	0,				ts_help_login, 0, NULL, NULL},
 	{"LOGOUT",	ss_cmd_logout,	0,	30,				ts_help_logout, 0, NULL, NULL},
	{"CHPASS",	ss_cmd_chpass,	1,	30,				ts_help_chpass, 0, NULL, NULL},
	{"ASSIST",	ss_cmd_assist,	2,	30,				ts_help_assist, 0, NULL, NULL},
	{"HELPERS",	ss_cmd_helpers,	1,	NS_ULEVEL_ADMIN,ts_help_helpers, 0, NULL, NULL},
	NS_CMD_END()
};

/** helper set list */
static bot_setting helper_settings[]=
{
	{"NOHELPMSG",	SecureServ.nohelp,		SET_TYPE_MSG,		0,	BUFSIZE,	NS_ULEVEL_ADMIN,NULL,	ts_help_set_nohelpmsg, NULL,( void * )"No Helpers are online at the moment, so you have been Akilled from this network. Please visit http://www.nohack.org for Trojan/Virus Info" },
	{"AUTOSIGNOUT",	&SecureServ.signoutaway,SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,NULL,	ts_help_set_autosignout, NULL,( void * )1 },
	{"JOINHELPCHAN",&SecureServ.joinhelpchan,SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,NULL,	ts_help_set_joinhelpchan, NULL,( void * )1 },
	NS_SETTING_END()
};

/** @brief HelpersStatus
 *
 *  STATUS
 *
 *  @param cmdparam struct
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

void HelpersStatus( const CmdParams *cmdparams )
{
	if( SecureServ.helpers == 1 )
		irc_prefmsg( ss_bot, cmdparams->source, "Helpers logged in: %d", SecureServ.helpcount );
}

/** @brief LoadHelper
 *
 *  Table load handler
 *  Database row handler to load helper data
 *
 *  @param data pointer to table row data
 *  @param size of loaded data
 *
 *  @return NS_TRUE to abort load or NS_FALSE to continue loading
 */

static int LoadHelper( void *data, int size )
{
	Helper *helper;

	helper = ns_malloc( sizeof( Helper ) );
	os_memcpy( helper, data, sizeof( Helper ) );
	helper->u = NULL;
	hnode_create_insert( helperhash, helper, helper->nick );
	return NS_FALSE;
}

/** @brief InitHelpers
 *
 *  Init helper subsystem
 *
 *  @param none
 *
 *  @return NS_SUCCESS if succeeds, NS_FAILURE if not 
 */

int InitHelpers( void ) 
{
	SET_SEGV_LOCATION();
	helperhash = hash_create( HASHCOUNT_T_MAX, 0, 0 );
	if( !helperhash )
	{
		nlog( LOG_CRITICAL, "Unable to create helperhash hash" );
		return NS_FAILURE;
	}
	DBAFetchRows( "helpers", LoadHelper );
	if( SecureServ.helpers == 1 )
	{
		add_bot_cmd_list( ss_bot, helper_commands );
		add_bot_setting_list( ss_bot, helper_settings );
	}
	return NS_SUCCESS;
}

/** @brief FiniHelpers
 *
 *  Fini helper subsystem
 *
 *  @param none
 *
 *  @return none
 */

void FiniHelpers( void ) 
{
	hscan_t hlps;
	hnode_t *node;
	Helper *helper;

	SET_SEGV_LOCATION();
	if( helperhash ) {
		hash_scan_begin( &hlps, helperhash );
		while( ( node = hash_scan_next( &hlps ) ) != NULL ) {
			helper = hnode_get( node );
			ClearUserModValue( helper->u );
			hash_delete( helperhash, node );
			hnode_destroy( node );
			ns_free( helper );
		}
		hash_destroy( helperhash );
	}
}

/** @brief HelperLogout
 *
 *  LOGOUT helper
 *
 *  @param cmdparam struct
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

static int HelperLogout( Client *c )
{
	UserDetail *ud;
	Helper *helper;
	
	SET_SEGV_LOCATION();
	ud = ( UserDetail * )GetUserModValue( c );
	if( ud && ud->type == USER_HELPER ) {
		helper = ( Helper * )ud->data;
		helper->u = NULL;
		ns_free( ud );
		ClearUserModValue( c );
		if( SecureServ.helpcount > 0 )
			SecureServ.helpcount--;
		if( ( SecureServ.helpcount == 0 ) &&( IsChannelMember( FindChannel( SecureServ.HelpChan ), ss_bot->u ) == 1 ) )
			irc_part( ss_bot, SecureServ.HelpChan, NULL );
		return NS_SUCCESS;
	}
	return NS_FAILURE;
}

/** @brief ss_cmd_chpass
 *
 *  CHPASS command handler
 *
 *  @param cmdparam struct
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

static int ss_cmd_chpass( const CmdParams *cmdparams ) 
{
	UserDetail *ud;
	Helper *helper;

	SET_SEGV_LOCATION();
	ud = ( UserDetail * )GetUserModValue( cmdparams->source );
	if( ud && ud->type == USER_HELPER ) {
		helper = ( Helper * )ud->data;
		strlcpy( helper->pass, cmdparams->av[0], MAXNICK );
		DBAStore( "helpers", helper->nick,( void * )helper, sizeof( Helper ) );
		irc_prefmsg( ss_bot, cmdparams->source, "Successfully changed your password" );
		irc_chanalert( ss_bot, "%s changed their helper password", cmdparams->source->name );
		return NS_SUCCESS;
	}
	irc_prefmsg( ss_bot, cmdparams->source, "You must be logged in to change your Helper Password" );
	return NS_SUCCESS;
}

/** @brief ss_cmd_login
 *
 *  LOGIN command handler
 *
 *  @param cmdparam struct
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

static int ss_cmd_login( const CmdParams *cmdparams ) 
{
	Helper *helper;
	UserDetail *ud;

	SET_SEGV_LOCATION();
	ud = ( UserDetail * )GetUserModValue( cmdparams->source );
	if( ud && ud->type == USER_HELPER ) {
		irc_prefmsg( ss_bot, cmdparams->source, "You are already logged in" );
		return NS_SUCCESS;
	}
	helper = ( Helper * )hnode_find( helperhash, cmdparams->av[0] );
	if( helper ) {
		if( ircstrcasecmp( helper->pass, cmdparams->av[1] ) == 0 )
		{
			Channel* c;

			c = FindChannel( SecureServ.HelpChan );
			helper->u = cmdparams->source;
			ud = ns_malloc( sizeof( UserDetail ) );
			ud->type = USER_HELPER;
			ud->data = ( void * ) helper;
			SetUserModValue( cmdparams->source,( void * )ud );
			irc_prefmsg( ss_bot, cmdparams->source, "Login Successful" );
			irc_chanalert( ss_bot, "%s logged in as a helper", cmdparams->source->name );
			if( ( SecureServ.joinhelpchan == 1 ) &&( IsChannelMember( c, ss_bot->u ) != 1 ) ) {
				irc_join( ss_bot, SecureServ.HelpChan, "+a" );//CUMODE_CHANADMIN );
			}
			if( IsChannelMember( c, cmdparams->source ) != 1 ) {
				irc_prefmsg( ss_bot, cmdparams->source, "Joining you to the Help Channel" );
				irc_svsjoin( ss_bot, cmdparams->source, SecureServ.HelpChan );
			}				                
			SecureServ.helpcount++;
			return NS_SUCCESS;
		}
		irc_prefmsg( ss_bot, cmdparams->source, "Login Failed" );
		irc_chanalert( ss_bot, "%s tried to login with %s, but got the pass wrong (%s)", cmdparams->source->name, cmdparams->av[0], cmdparams->av[1] );
		return NS_SUCCESS;
	} 
	irc_prefmsg( ss_bot, cmdparams->source, "Login Failed" );
	irc_chanalert( ss_bot, "%s tried to login with %s but that account does not exist", cmdparams->source->name, cmdparams->av[0] );
	return NS_SUCCESS;
}

/** @brief ss_cmd_logout
 *
 *  LOGOUT command handler
 *
 *  @param cmdparam struct
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

static int ss_cmd_logout( const CmdParams *cmdparams )
{
	if( HelperLogout( cmdparams->source ) == NS_SUCCESS )
	{
		irc_chanalert( ss_bot, "%s logged out from helper system", cmdparams->source->name );
		irc_prefmsg( ss_bot, cmdparams->source, "You are now logged out" );
	}
	else
	{
		irc_prefmsg( ss_bot, cmdparams->source, "Error, You do not appear to be logged in" );
	}
	return NS_SUCCESS;
}

/** @brief ss_cmd_assist_release
 *
 *  ASSIST RELEASE command handler
 *
 *  @param cmdparam struct
 *  @param tu pointer to target client struct
 *  @param td pointer to target client details struct
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

static int ss_cmd_assist_release( const CmdParams *cmdparams, Client *tu, UserDetail *td )
{
	ClearUserModValue( tu );
	td->data = NULL;
	ns_free( td );
	irc_prefmsg( ss_bot, cmdparams->source,  "Hold on %s is released", tu->name );
	irc_chanalert( ss_bot, "%s released %s", cmdparams->source->name, tu->name );
	return NS_SUCCESS;
}

/** @brief ss_cmd_assist_kill
 *
 *  ASSIST KILL command handler
 *
 *  @param cmdparam struct
 *  @param tu pointer to target client struct
 *  @param td pointer to target client details struct
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

static int ss_cmd_assist_kill( const CmdParams *cmdparams, Client *tu, UserDetail *td )
{
	virientry *ve;

	ve = ( virientry * )td->data;
	irc_prefmsg( ss_bot, cmdparams->source, "Akilling %s as they are infected with %s", tu->name, ve->name );	
	irc_chanalert( ss_bot, "%s used assist kill on %s!%s@%s( infected with %s )", cmdparams->source->name, tu->name, tu->user->username, tu->user->hostname, ve->name );
	nlog( LOG_NORMAL, "%s used assist kill on %s!%s@%s( infected with %s )", cmdparams->source->name, tu->name, tu->user->username, tu->user->hostname, ve->name );
	if( ve->iscustom )
	{
		irc_globops( ss_bot, "Akilling %s for Virus %s( Helper %s performed Assist Kill )", tu->name, ve->name, cmdparams->source->name );
		irc_akill( ss_bot, tu->user->hostname, tu->user->username, SecureServ.akilltime, "Infected with Virus/Trojan %s.( HelperAssist by %s )", ve->name, cmdparams->source->name );
	}
	else
	{
		irc_globops( ss_bot, "Akilling %s for Virus %s( Helper %s performed Assist Kill )( http://secure.irc-chat.net/info.php?viri=%s )", tu->name, ve->name, cmdparams->source->name, ve->name );
		irc_akill( ss_bot, tu->user->hostname, tu->user->username, SecureServ.akilltime, "Infected with Virus/Trojan. Visit http://secure.irc-chat.net/info.php?viri=%s( HelperAssist by %s )", ve->name, cmdparams->source->name );
	}
	return NS_SUCCESS;
}

/** @brief ss_cmd_assist
 *
 *  ASSIST command handler
 *
 *  @param cmdparam struct
 *    cmdparams->av[0] = subcommand (RELEASE, KILL)
 *    cmdparams->av[1] = target user nick
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

static int ss_cmd_assist( const CmdParams *cmdparams )
{
	UserDetail *ud, *td;
	Client *tu;

	SET_SEGV_LOCATION();
	/* Check source user authority */
	ud = ( UserDetail * )GetUserModValue( cmdparams->source );
	if( !ud || ud->type != USER_HELPER )
	{
		irc_prefmsg( ss_bot, cmdparams->source, "Access Denied" );
		irc_chanalert( ss_bot, "%s tried to use assist %s on %s, but is not logged in", cmdparams->source->name, cmdparams->av[0], cmdparams->av[1] );
		return NS_SUCCESS;
	}
	/* Check target user */
	tu = FindUser( cmdparams->av[1] );
	if( !tu )
		return NS_SUCCESS;
	td = GetUserModValue( tu );
	if( !td || td->type != USER_INFECTED ) {
		irc_prefmsg( ss_bot, cmdparams->source, "Invalid User %s. Not Recorded as requiring assistance", tu->name );
		irc_chanalert( ss_bot, "%s tried to use assist %s on %s, but the target is not requiring assistance", cmdparams->source->name, cmdparams->av[0], cmdparams->av[1] );
		return NS_SUCCESS;
	}
	/* call sub command handler */
	if( ircstrcasecmp( cmdparams->av[0], "RELEASE" ) == 0 )
		return ss_cmd_assist_release( cmdparams, tu, td );
	if( ircstrcasecmp( cmdparams->av[0], "KILL" ) == 0 )
		return ss_cmd_assist_kill( cmdparams, tu, td );
	return NS_ERR_SYNTAX_ERROR;
}	

/** @brief ss_cmd_helpers_add
 *
 *  HELPERS ADD command handler
 *
 *  @param cmdparam struct
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

static int ss_cmd_helpers_add( const CmdParams *cmdparams ) 
{
	Helper *helper;
	hnode_t *node;
	
	SET_SEGV_LOCATION();
	if( cmdparams->ac < 3 )
		return NS_ERR_NEED_MORE_PARAMS;
	if( hash_lookup( helperhash, cmdparams->av[1] ) )
	{
		irc_prefmsg( ss_bot, cmdparams->source, "Helper login %s already exists", cmdparams->av[1] );
		return NS_SUCCESS;
	}
	helper = ns_malloc( sizeof( Helper ) );
	strlcpy( helper->nick, cmdparams->av[1], MAXNICK );
	strlcpy( helper->pass, cmdparams->av[2], MAXNICK );
	helper->u = NULL;
	node = hnode_create( helper );
 	hash_insert( helperhash, node, helper->nick );

	/* ok, now save the helper */
	DBAStore( "helpers", helper->nick,( void * )helper, sizeof( Helper ) );
	irc_prefmsg( ss_bot, cmdparams->source, "Helper %s added with password %s", helper->nick, helper->pass );
	return NS_SUCCESS;
}

/** @brief ss_cmd_helpers_del
 *
 *  HELPERS DEL command handler
 *
 *  @param cmdparam struct
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

static int ss_cmd_helpers_del( const CmdParams *cmdparams ) 
{
	hnode_t *node;

	SET_SEGV_LOCATION();
	if( cmdparams->ac < 2 ) {
		return NS_ERR_NEED_MORE_PARAMS;
	}
	node = hash_lookup( helperhash, cmdparams->av[1] );
	if( node )
	{
		hash_delete( helperhash, node );
		ns_free( hnode_get( node ) );
		hnode_destroy( node );
		DBADelete( "helpers", cmdparams->av[1] );
		irc_prefmsg( ss_bot, cmdparams->source, "Helper %s deleted", cmdparams->av[1] );
	}
	else
	{
		irc_prefmsg( ss_bot, cmdparams->source, "Error, helper %s not found. /msg %s helpers list", cmdparams->av[1], ss_bot->name );
	}
	return NS_SUCCESS;
}

/** @brief ss_cmd_helpers_list
 *
 *  HELPERS LIST command handler
 *
 *  @param cmdparam struct
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

static int ss_cmd_helpers_list( const CmdParams *cmdparams ) 
{
	hscan_t hlps;
	hnode_t *node;
	Helper *helper;

	SET_SEGV_LOCATION();
	irc_prefmsg( ss_bot, cmdparams->source, "Helpers list( %d ):",( int )hash_count( helperhash ) );
	hash_scan_begin( &hlps, helperhash );
	while( ( node = hash_scan_next( &hlps ) ) != NULL )
	{
		helper = hnode_get( node );
		irc_prefmsg( ss_bot, cmdparams->source, "%s( %s )", helper->nick, helper->u ? helper->u->name : "Not Logged In" );
	}
	irc_prefmsg( ss_bot, cmdparams->source, "End of list." );	
	return NS_SUCCESS;
}

/** @brief ss_cmd_helpers
 *
 *  HELPERS command handler
 *
 *  @param cmdparam struct
 *    cmdparams->av[0] = subcommand( one of ADD, DEL, LIST )
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

static int ss_cmd_helpers( const CmdParams *cmdparams )
{
	SET_SEGV_LOCATION();
	if( ircstrcasecmp( cmdparams->av[0], "ADD" ) == 0 )
		return ss_cmd_helpers_add( cmdparams );
	if( ircstrcasecmp( cmdparams->av[0], "DEL" ) == 0 )
		return ss_cmd_helpers_del( cmdparams );
	if( ircstrcasecmp( cmdparams->av[0], "LIST" ) == 0 )
		return ss_cmd_helpers_list( cmdparams );
	return NS_ERR_SYNTAX_ERROR;
}

/** @brief HelpersSignoff
 *
 *  SIGNOFF event handler
 *  handle away
 *
 *  @params cmdparams pointer to commands param struct
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

int HelpersSignoff( Client *c ) 
{
	if( SecureServ.helpers != 1 )
		return NS_SUCCESS;
	if( HelperLogout( c ) == NS_SUCCESS )
	{
		irc_chanalert( ss_bot, "%s logged out for quit", c->name );
	}
	return NS_SUCCESS;
}

/** @brief HelpersAway
 *
 *  AWAY event handler
 *  handle away
 *
 *  @params cmdparams pointer to commands param struct
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

int HelpersAway( const CmdParams *cmdparams ) 
{
	SET_SEGV_LOCATION();
	if( SecureServ.helpers != 1 )
		return NS_SUCCESS;
	if( SecureServ.signoutaway != 1 )
		return NS_SUCCESS;
	if( HelperLogout( cmdparams->source ) == NS_SUCCESS )
	{
		irc_chanalert( ss_bot, "%s logged out after set away", cmdparams->source->name );
		irc_prefmsg( ss_bot, cmdparams->source, "You have been logged out of SecureServ" );
	}
	return NS_SUCCESS;
}

/** @brief ss_cmd_set_helpers_cb
 *
 *  Set callback for set helpers
 *  Enable or disable commands associated with helper system
 *
 *  @params cmdparams pointer to commands param struct
 *  @params reason for SET
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

int ss_cmd_set_helpers_cb( const CmdParams *cmdparams, SET_REASON reason ) 
{
	if( reason == SET_CHANGE )
	{
		if( SecureServ.helpers == 1 )
		{
			add_bot_cmd_list( ss_bot, helper_commands );
			add_bot_setting_list( ss_bot, helper_settings );
		}
		else
		{
			del_bot_cmd_list( ss_bot, helper_commands );
			del_bot_setting_list( ss_bot, helper_settings );
		}
	}
	return NS_SUCCESS;
}
