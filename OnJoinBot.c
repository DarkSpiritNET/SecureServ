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
** $Id: OnJoinBot.c 414 2007-07-30 10:49:09Z DNB $
*/

#include "SecureServ.h"

#define MAX_NICKS 100
#define DEFAULT_VERSION_RESPONSE "Visual IRC 2.0rc5 (English) - Fast. Powerful. Free. http://www.visualirc.net/beta.php"

static char lastchan[MAXCHANLEN];
static char lastnick[MAXNICK];

static BotInfo defaultbots[]= 
{
	{
		"Bob",
		"Bob",
		"Blah",
		"cp127.ppp0.singnet.com.sg",
		"Can't Get Enough",
		0,
		NULL,
		NULL
	},
	{
		"Sven",
		"Sven",
		"Sven",
		"h48n3c1.bredband.skanova.com",
		"Sven",
		0,
		NULL,
		NULL
	},
	{
		"Scarab",
		"Scarab",
		"~email",
		"dsl-283-923-23-847.arcor-ip.net.jp",
		"Mr Qaz",
		0,
		NULL,
		NULL
	},
	{
		"Cledus",
		"Cledus",
		"~Fud1",
		"ip768-14-131-1924.uh.ix.cox.net",
		"fwsgh1",
		0,
		NULL,
		NULL
	},
	{
		"Rubarb",
		"Rubarb",
		"ident",
		"dialup-01.kpa.ida.myisp.id",
		"Chat to me",
		0,
		NULL,
		NULL
	},
	{
		"ShangMan",
		"ShangMan",
		"ShangMan",
		"adsl-204-12-85-12.ma.us.rogers.com",
		"I'm to lame to read BitchX.doc",
		0,
		NULL,
		NULL
	},
	{
		"VJTD3",
		"VJTD3",
		"VJTD3",
		"ppp203.net267.fl.sprint-hsd.net",
		"VJTD3",
		0,
		NULL,
		NULL
	},
	{
		"static",
		"static",
		"nobody",
		"adsl463.lqd.adsl.inernode.on.net",
		"Tim",
		0,
		NULL,
		NULL
	},
	{
		"BluD",
		"BluD",
		"~blud",
		"592-12.021.popsite.net",
		"BluD",
		0,
		NULL,
		NULL
	},
};

static list_t *monchans;
/* this is the list of random nicknames */
static list_t *nicks;
char onjoinbot_modes[MODESIZE] = "+";
static Bot *monbotptr;
static Bot *ojbotptr;

void OnJoinBotStatus( const CmdParams *cmdparams )
{
	if( lastchan[0] )
		irc_prefmsg( ss_bot, cmdparams->source, "Currently checking %s with %s", lastchan, lastnick );
}

static int chkmonchan( const void *key1, const void *key2 )
{
	char *chan =( char * )key1;
	char *chk =( char * )key2;
	return( ircstrcasecmp( chan, chk ) );
}

static Channel *GetNewChan( void )
{
	Channel *c;
	int i;

	for( i = 0; i < 5; i++ )
	{
		c = GetRandomChannel();
		if( c == NULL )
		{
			dlog( DEBUG1, "Hu? Couldn't find a channel" );
			break;
		}
		dlog( DEBUG1, "Random Chan is %s", c->name );
		/* if channel is private and setting is enabled, don't join */
		if( ( SecureServ.doprivchan == 0 ) &&( is_priv_chan( c ) ) )
		{
			dlog( DEBUG1, "Not Scanning %s, as its a private channel", c->name );
			continue;
		}
		if( ircstrcasecmp( lastchan, c->name )== 0 )
		{
			/* this was the last channel we joined, don't join it again */
			dlog( DEBUG1, "Not Scanning %s, as we just did it", c->name );
			continue;
		}
		/* if the channel is exempt, restart */
		if( SS_IS_CHANNEL_EXCLUDED( c ) )
		{
			continue;
		}
		/* if we are already monitoring with a monbot, don't join */
		if( list_find( monchans, c->name, chkmonchan ) )
		{
			dlog( DEBUG1, "Not Scanning %s as we are monitoring it with a monbot",c->name );
			continue;
		}
		return( c );
	}
	/* give up after 5 attempts */
	dlog( DEBUG1, "Couldn't find a fresh Channel, Giving up" );
	lastchan[0] = 0;
	lastnick[0] = 0;
	return NULL;
}

static BotInfo *GetNewBot( int resetflag )
{
	BotInfo *nickname = NULL;
	lnode_t *rnn;
	int i;
	unsigned int randno, curno, stublen;

	if( list_count( nicks ) == 0 )
	{
		/* No bots available */
		dlog( DEBUG1, "No bots available, giving up" );
		return NULL;
	}

	if( list_count( nicks ) == 1 )
	{
		/* If only one bot, no need for random which crashes with 1 anyway
		 * so just return the single bot */
		rnn = list_first( nicks );
		if( rnn != NULL )
		{
			nickname = lnode_get( rnn );
			/* make sure nick and altnick are the same */
			strlcpy( nickname->altnick, nickname->nick, MAXNICK );
			/* make sure no one is online with this nickname */
			if( FindUser( nickname->nick ) != NULL )
			{
				dlog( DEBUG1, "%s is online, can't use that nick", nickname->nick );
				/* Try to auto generate a altnick from bot nick */
				strlcpy( nickname->altnick, nickname->nick, MAXNICK );
				stublen = strlen( nickname->altnick );
				for( i = 0 ; i < 5 ; i++ )
				{
					if( GenerateBotNick( nickname->altnick, stublen , 0,( i + 1 ) ) == NS_SUCCESS )
						return nickname;
				}
				return NULL;
			}
			dlog( DEBUG1, "RandomNick is %s", nickname->nick );
			return nickname;
		}
		return NULL;
	}

	for( i = 0; i < 5; i++ )
	{
		curno = 1;
		randno = hrand( list_count( nicks )-1, 0 );
		rnn = list_first( nicks );
		while( rnn != NULL )
		{
			if( curno == randno )
			{
				nickname = lnode_get( rnn );
				if( ircstrcasecmp( nickname->nick, lastnick )== 0 )
				{
					/* its the same as last time, nope */
					dlog( DEBUG1, "%s was used last time. Retring", nickname->nick );
					break;
				}
				/* make sure nick and altnick are the same */
				strlcpy( nickname->altnick, nickname->nick, MAXNICK );
				/* make sure no one is online with this nickname */
				if( FindUser( nickname->nick ) != NULL )
				{
					dlog( DEBUG1, "%s is online, can't use that nick, retring", nickname->nick );
					/* Try to auto generate a altnick from bot nick */
					strlcpy( nickname->altnick, nickname->nick, MAXNICK );
					stublen = strlen( nickname->altnick );
					for( i = 0 ; i < 5 ; i++ )
					{
						if( GenerateBotNick( nickname->altnick, stublen , 0,( i + 1 ) ) == NS_SUCCESS )
							return nickname;
					}
					break;
				}
				dlog( DEBUG1, "RandomNick is %s", nickname->nick );
				return nickname;
			}
			curno++;
			rnn = list_next( nicks, rnn );
		}
	}
	/* give up if we try five times */
	dlog( DEBUG1, "Couldn't find a free nickname, giving up" );
	if( resetflag )
	{
		lastchan[0] = 0;
		lastnick[0] = 0;
	}
	return NULL;
}

int MonBotCycle( void *userptr )
{
	lnode_t *mcnode;
	Channel *c;
	char *chan;
	/* cycle one monchan, if configured to */
	if( SecureServ.monbot[0] == 0 )
		return NS_SUCCESS;
	if( SecureServ.monchancycle > 0 )
	{
		mcnode = list_first( monchans );
		while( mcnode != NULL )
		{
			chan = lnode_get( mcnode );
			if( chan )
			{
				c = FindChannel( chan );
				if( c == NULL )
				{
					/* channel isn't online atm, ignore */
					mcnode = list_next( monchans, mcnode );
					continue;
				}
				if( IsChannelMember( c, FindUser( SecureServ.monbot ) ) )
				{
					irc_part( monbotptr, c->name, NULL );
				}
				irc_join( monbotptr, c->name, 0 );
			}
			mcnode = list_next( monchans, mcnode );
		}
	}
	return NS_SUCCESS;
}

static int cycle_onjoin_chan( void )
{
	Channel *c;
	BotInfo *nickname = NULL;

	SET_SEGV_LOCATION();
	/* first, if the lastchan and last nick are not empty, it means one of our bots is in a chan, sign them off */
	if( lastnick[0] != 0 )
	{
		if( FindUser( lastnick ) )
		{
			if( lastchan[0] != 0 )
			{
				irc_part( ojbotptr, lastchan, NULL );
			}
			irc_quit( ojbotptr, "Finished Scanning" );
			ojbotptr = NULL;
			lastchan[0] = 0;
			lastnick[0] = 0;
		}
	}
	/* if we don't do OnJoin Checking, Don't go any further */
	if( SecureServ.DoOnJoin < 1 )
		return NS_SUCCESS;
	if( list_count( nicks ) < 1 )
	{
		/* just broadcast a error every time we try, till a admin either turns of Onjoin checking, or adds a few bots */
		irc_chanalert( ss_bot, "Warning!!! BotList is empty. We cant do OnJoin Checking. Add a few bots via ./msg %s bots command", ss_bot->name );
		return NS_SUCCESS;
	}
	c = GetNewChan();
	if( c == NULL )
		return NS_SUCCESS;
	strlcpy( lastchan, c->name, MAXCHANLEN );
	nickname = GetNewBot( 1 );
	if( nickname == NULL )
		return NS_SUCCESS;
	strlcpy( lastnick, nickname->nick, MAXNICK );
	/* ok, init the new bot. */
	ojbotptr = AddBot( nickname );
	if( ojbotptr == NULL )
	{
		lastchan[0] = 0;
		lastnick[0] = 0;
		nlog( LOG_WARNING, "init_bot reported nick was in use. How? Dunno" );
		return NS_SUCCESS;
	}
	irc_umode( ojbotptr, ojbotptr->u->name, UmodeStringToMask( onjoinbot_modes ) );
	irc_cloakhost( ojbotptr );
	irc_join( ojbotptr, c->name, 0 );
	if( SecureServ.verbose )
	{
		if( ircstrcasecmp( nickname->nick, nickname->altnick )== 0 )
			irc_chanalert( ss_bot, "Scanning %s with %s for OnJoin Viruses", c->name, nickname->nick );
		else
			irc_chanalert( ss_bot, "Scanning %s with %s as %s for OnJoin Viruses", c->name, nickname->nick, nickname->altnick );
	}
	return NS_SUCCESS;
}

int JoinNewChan( void *userptr )
{
	cycle_onjoin_chan();
	return NS_SUCCESS;
}

int ss_event_versionrequest( const CmdParams *cmdparams )
{
	nlog( LOG_NORMAL, "Received version request from %s to OnJoin Bot %s", cmdparams->source->name, cmdparams->bot->name );
	irc_notice( cmdparams->bot, cmdparams->source, "\1VERSION %s\1", SecureServ.sampleversion );
	return NS_SUCCESS;
}

int ss_event_message( const CmdParams *cmdparams )
{
	SET_SEGV_LOCATION();
	/* check if this user is exempt */
	if( ModIsUserExcluded( cmdparams->source ) == NS_TRUE )
	{
		dlog( DEBUG1, "User %s is exempt from Message Checking", cmdparams->source->name );
		return NS_SUCCESS;
	}
	nlog( LOG_NORMAL, "Received message from %s to OnJoin Bot %s: %s", cmdparams->source->name, cmdparams->bot->name, cmdparams->param );
	if( SecureServ.verbose||SecureServ.BotEcho )
	{
		irc_chanalert( ss_bot, "OnJoin Bot %s Received Private Message from %s: %s", cmdparams->bot->name, cmdparams->source->name, cmdparams->param );
	}
	ScanPrivmsg( cmdparams->source, cmdparams->param );
	return NS_SUCCESS;
}				

int ss_event_kickbot( const CmdParams *cmdparams )
{
	lnode_t *mn;
	
	SET_SEGV_LOCATION();
	/* check its one of our nicks */
	if( ircstrcasecmp( lastnick, cmdparams->target->name ) == 0 &&( ircstrcasecmp( lastchan, cmdparams->channel->name )== 0 ) )
	{
		nlog( LOG_NOTICE, "Our Bot %s was kicked from %s", cmdparams->target->name, cmdparams->channel->name );
		lastchan[0] = 0;
		return NS_SUCCESS;
	}
	if( SecureServ.monbot[0] == 0 )
	{
		return NS_SUCCESS;
	}
	/* if its our monbot, rejoin the channel! */
	if( cmdparams->bot == monbotptr )
	{
		mn = list_first( monchans );
		while( mn != NULL )
		{
			if( ircstrcasecmp( cmdparams->channel->name, lnode_get( mn ) )== 0 )
			{
				/* rejoin the monitor bot to the channel */
				irc_join( monbotptr, cmdparams->channel->name, 0 );
				if( SecureServ.verbose )
				{
					irc_chanalert( ss_bot, "%s was kicked out of monitored channel %s by %s. Rejoining", cmdparams->target->name, cmdparams->channel->name, cmdparams->source->name );
				}
				nlog( LOG_NOTICE, "%s was kicked out of monitored channel %s by %s. Rejoining", cmdparams->target->name, cmdparams->channel->name, cmdparams->source->name );
				return NS_SUCCESS;
			}
			mn = list_next( monchans, mn );
		}
		return NS_SUCCESS;
	}					
	return NS_SUCCESS;
}

static int InitMonBot( void )
{
	BotInfo *nickname = NULL;
	lnode_t *rnn;

	rnn = list_first( nicks );
	while( rnn != NULL )
	{
		nickname = lnode_get( rnn );
		if( ircstrcasecmp( nickname->nick, SecureServ.monbot )== 0 )
		{
			/* its our bot */
			break;
		}
		rnn = list_next( nicks, rnn );
	}
	if( rnn == NULL )
	{
		nlog( LOG_WARNING, "Warning, MonBot %s isn't available!", SecureServ.monbot );			
		return NS_FALSE;
	}
	monbotptr = AddBot( nickname );
	if( monbotptr == NULL )
	{
		return NS_FALSE;
	}
	irc_umode( monbotptr, monbotptr->u->name, UmodeStringToMask( onjoinbot_modes ) );
	irc_cloakhost( monbotptr );
	return NS_TRUE;
}

int MonJoin( const Channel *c )
{
	lnode_t *mn;

	if( SecureServ.monbot[0] == 0 )
	{
		return -1;
	}
	mn = list_first( monchans );
	while( mn != NULL )
	{
		if( ircstrcasecmp( c->name, lnode_get( mn ) )== 0 )
		{
			if( monbotptr == NULL )
			{
				/* the monbot isn't online. Initilze it */
				if( InitMonBot() != NS_TRUE )
				{
					return 1;
				}
			}
			/* if they the monbot is not a member of the channel, join it. */
			if( !IsChannelMember( c, monbotptr->u ) )
			{
				/* join the monitor bot to the new channel */
				irc_join( monbotptr, c->name, 0 );
			}	
			return 1;
		}
		mn = list_next( monchans, mn );
	}
	return 1;
}	

static Channel *MonChan( Client *u, char *requestchan )
{
	Channel *c;
	lnode_t *mn;
	char *buf;
	
	SET_SEGV_LOCATION();

	if( list_isfull( monchans ) )
	{
		if( u )
			irc_prefmsg( ss_bot, u, "Unable to monitor any additional channels" );
		nlog( LOG_WARNING, "MonChan List is full. Not Monitoring %s", requestchan );
		return NULL;
	}

	mn = list_first( monchans );
	while( mn != NULL )
	{
		if( ircstrcasecmp( requestchan, lnode_get( mn ) )== 0 )
		{
			if( u ) irc_prefmsg( ss_bot, u, "Already Monitoring Channel %s", requestchan );
			return NULL;
		}
		mn = list_next( monchans, mn );
	}
	c = FindChannel( requestchan );
	if( c == NULL )
	{
		if( u )
			irc_prefmsg( ss_bot, u, "Unable to find channel %s.", requestchan );
		return NULL;
	}			
	/* dont allow excepted channels */
	if( SS_IS_CHANNEL_EXCLUDED( c ) )
	{
		if( u )
			irc_prefmsg( ss_bot, u, "Can't monitor a channel listed as a Exclude Channel" );
		return NULL;
	}
	if( SecureServ.monbot[0] == 0 )
	{
		if( u )
			irc_prefmsg( ss_bot, u, "Warning, No Monitor Bot set. /msg %s help set", ss_bot->name );
		return NULL;
	}
	if( monbotptr == NULL )
	{
		/* the monbot isn't online. Initilze it */
		if( InitMonBot() != NS_TRUE )
		{
			return NULL;
		}
	}
	/* append it to the list */
	buf = ns_calloc( MAXCHANLEN );
	strlcpy( buf, requestchan, MAXCHANLEN );
	lnode_create_append( monchans, buf );
	/* join the monitor bot to the new channel */
	irc_join( monbotptr, c->name, 0 );
	if( SecureServ.verbose )
		irc_chanalert( ss_bot, "Monitoring %s with %s for Viruses by request of %s", c->name, SecureServ.monbot, u ? u->name : ss_bot->name );
	if( u )
		irc_prefmsg( ss_bot, u, "Monitoring %s with %s", c->name, SecureServ.monbot );
	return c;
}

static int ss_cmd_monchan_add( const CmdParams *cmdparams )
{
	Channel *c;

	if( cmdparams->ac < 2 )
	{
		return NS_ERR_NEED_MORE_PARAMS;
	}
	c = MonChan( cmdparams->source, cmdparams->av[1] );
	/* dont save in MonChan, as thats also called by LoadChan */
	if( c != NULL )
		DBAStoreStr( "monchans", c->name, c->name, MAXCHANLEN );
	return NS_SUCCESS;
}

static int ss_cmd_monchan_del( const CmdParams *cmdparams )
{
	char *chan;
	lnode_t *node;

	SET_SEGV_LOCATION();
	if( cmdparams->ac < 2 )
	{
		return NS_ERR_NEED_MORE_PARAMS;
	}
	node = list_find( monchans, cmdparams->av[1], chkmonchan );
	if( node == NULL )
	{
		irc_prefmsg( ss_bot, cmdparams->source, "Couldn't find channel %s in monitored channel list", cmdparams->av[1] );
		return NS_FAILURE;
	}
	chan = lnode_get( node );
	DBADelete( "monchans", chan );
	irc_prefmsg( ss_bot, cmdparams->source, "Deleted %s out of monitored channel list.",( char* )lnode_get( node ) );
	irc_part( monbotptr, cmdparams->av[1], NULL );
	lnode_destroy( list_delete( monchans, node ) );
	ns_free( chan );
	return NS_SUCCESS;
}		

static int ss_cmd_monchan_list( const CmdParams *cmdparams )
{
	lnode_t *node;

	SET_SEGV_LOCATION();
	irc_prefmsg( ss_bot, cmdparams->source, "Monitored Channels List( %d ):",( int )list_count( monchans ) );
	node = list_first( monchans );
	while( node != NULL )
	{
		irc_prefmsg( ss_bot, cmdparams->source, "%s",( char* )lnode_get( node ) );
		node = list_next( monchans, node );
	}
	irc_prefmsg( ss_bot, cmdparams->source, "End of list" );
	return 1;
}

static int LoadMonChan( void *data, int size )
{
	Channel *c;
	
	c = MonChan( NULL,( char * )data );
	return NS_FALSE;
}

int LoadMonChans( void )
{
	SET_SEGV_LOCATION();
	monchans = list_create( 20 );
	DBAFetchRows( "monchans", LoadMonChan );
	return 1;
}

static int LoadRandomNick( void *data, int size )
{
	BotInfo *rnicks;

	rnicks = ns_calloc( sizeof( BotInfo ) );
	os_memcpy( rnicks, data, sizeof( BotInfo ) );
	dlog( DEBUG2, "Adding Random Nick %s!%s@%s with RealName %s", rnicks->nick, rnicks->user, rnicks->host, rnicks->realname );
	lnode_create_append( nicks, rnicks );
	return NS_FALSE;
}

static void LoadDefaultNicks( void )
{
	BotInfo *rnicks;
	int i;

	for( i = 0; i <( sizeof( defaultbots )/sizeof( BotInfo ) ); i++ )
	{
		rnicks = ns_calloc( sizeof( BotInfo ) );
		os_memcpy( rnicks, &defaultbots[i], sizeof( BotInfo ) );
		dlog( DEBUG2, "Adding Random Nick %s!%s@%s with RealName %s", rnicks->nick, rnicks->user, rnicks->host, rnicks->realname );
		lnode_create_append( nicks, rnicks );
	}
}


int InitOnJoinBots( void )
{
	BotInfo *rnicks;
	lnode_t *node;

	SET_SEGV_LOCATION();
	/* init the random nicks list */
	nicks = list_create( MAX_NICKS );
	/* init CTCP version response */
	strlcpy( SecureServ.sampleversion, DEFAULT_VERSION_RESPONSE, SS_BUF_SIZE );
	/* get Random Nicknames */
	if( DBAFetchRows( "randomnicks", LoadRandomNick ) == 0 )
	{
		LoadDefaultNicks();
	}
	if( DBAFetchConfigStr( "MonBot", SecureServ.monbot, MAXNICK ) != NS_SUCCESS )
	{
		SecureServ.monbot[0] = '\0';
	}
	else
	{
		node = list_first( nicks );
		while( node != NULL )
		{
			rnicks = lnode_get( node );
			if( ircstrcasecmp( rnicks->nick, SecureServ.monbot )== 0 )
			{
				/* ok, got the bot ! */
				break;
			}
			node = list_next( nicks, node );
		}
		if( node == NULL )
		{
			dlog( DEBUG2, "Warning, Cant find nick %s in random bot list for monbot", SecureServ.monbot );
			SecureServ.monbot[0] = '\0';
		}
	}
	return 1;
}

void FiniOnJoinBots( void )
{
	SET_SEGV_LOCATION();
	if( ojbotptr )
	{
		irc_chanalert( ss_bot, "SecureServ is unloading, OnJoinBot %s leaving", lastnick );
		if( lastchan[0] != 0 )
		{
			irc_part( ojbotptr, lastchan, NULL );
		}
		irc_quit( ojbotptr, SecureServ.botquitmsg );
		lastchan[0] = 0;
		lastnick[0] = 0;
	}
	if( SecureServ.monbot[0] != 0 )
	{
		irc_chanalert( ss_bot, "SecureServ is unloading, monitor bot %s leaving", SecureServ.monbot );
		irc_quit( monbotptr, SecureServ.botquitmsg );
	}
}

static int ss_cmd_bots_list( const CmdParams *cmdparams )
{
	lnode_t *node;
	BotInfo *bots;

	node = list_first( nicks );
	irc_prefmsg( ss_bot, cmdparams->source, "Bot List:" );
	while( node )
	{
		bots = lnode_get( node );
		irc_prefmsg( ss_bot, cmdparams->source, "%s (%s@%s) - %s", bots->nick, bots->user, bots->host, bots->realname );
 		node = list_next( nicks, node );
	}
	irc_prefmsg( ss_bot, cmdparams->source, "End of list." );
	CommandReport( ss_bot, "%s requested Bot List", cmdparams->source->name );
	return NS_SUCCESS;
}

static int ss_cmd_bots_add( const CmdParams *cmdparams )
{
	char *buf2;
	BotInfo *bots;

	if( cmdparams->ac < 5 )
	{
		return NS_ERR_NEED_MORE_PARAMS;
	}
	if( list_isfull( nicks ) )
	{
		irc_prefmsg( ss_bot, cmdparams->source, "Error, Bot list is full" );
		return NS_SUCCESS;
	}
	bots = ns_calloc( sizeof( BotInfo ) );
	strlcpy( bots->nick, cmdparams->av[1], MAXNICK );
	strlcpy( bots->user, cmdparams->av[2], MAXUSER );
	strlcpy( bots->host, cmdparams->av[3], MAXHOST );
	buf2 = joinbuf( cmdparams->av, cmdparams->ac, 4 );
	strlcpy( bots->realname, buf2, MAXREALNAME );
	ns_free( buf2 );
	lnode_create_append( nicks, bots );
	DBAStore( "randomnicks", cmdparams->av[1], bots, sizeof( BotInfo ) );
	irc_prefmsg( ss_bot, cmdparams->source, "Added %s (%s@%s - %s) Bot to Bot list", bots->nick, bots->user, bots->host, bots->realname );
	CommandReport( ss_bot, "%s added %s (%s@%s - %s) Bot to Bot list", cmdparams->source->name, bots->nick, bots->user, bots->host, bots->realname );
	return NS_SUCCESS;
}

static int ss_cmd_bots_del( const CmdParams *cmdparams )
{
	lnode_t *node;
	BotInfo *bots;

	if( cmdparams->ac < 2 )
	{
		return NS_ERR_NEED_MORE_PARAMS;
	}
	/* dont delete the bot if its setup as the monbot */
	if( ircstrcasecmp( cmdparams->av[1], SecureServ.monbot )== 0 )
	{
		irc_prefmsg( ss_bot, cmdparams->source, "Cant delete %s from botlist as its set as the monitor Bot", cmdparams->av[1] );
		return NS_FAILURE;
	}
	/* don't delete the bot if its online! */
	if( FindBot( cmdparams->av[1] ) )
	{
		irc_prefmsg( ss_bot, cmdparams->source, "Can't delete %s from botlist as its online at the moment", cmdparams->av[1] );
		return NS_FAILURE;
	}
	node = list_first( nicks );
	while( node != NULL )
	{
		bots = lnode_get( node );
		if( ircstrcasecmp( bots->nick, cmdparams->av[1] )== 0 )
		{
			/* ok, got the bot ! */
			break;
		}
		node = list_next( nicks, node );
	}
	if( node == NULL )
	{
		/* if we get here, then we can't find the entry */
		irc_prefmsg( ss_bot, cmdparams->source, "Error, Can't find bot %s", cmdparams->av[1] );
		return NS_SUCCESS;
	}

	/* delete the entry */
	list_delete( nicks, node );
	DBADelete( "randomnicks", bots->nick );				
	irc_prefmsg( ss_bot, cmdparams->source, "Deleted %s out of Bot list", bots->nick );
	CommandReport( ss_bot, "%s deleted %s out of bot list", cmdparams->source->name, bots->nick );
	lnode_destroy( node );
	ns_free( bots );
	return NS_SUCCESS;
}

int ss_cmd_bots( const CmdParams *cmdparams )
{
	SET_SEGV_LOCATION();
	if( ircstrcasecmp( cmdparams->av[0], "ADD" )== 0 )
		return ss_cmd_bots_add( cmdparams );
	if( ircstrcasecmp( cmdparams->av[0], "DEL" )== 0 )
		return ss_cmd_bots_del( cmdparams );
	if( ircstrcasecmp( cmdparams->av[0], "LIST" )== 0 )
		return ss_cmd_bots_list( cmdparams );
	return NS_ERR_SYNTAX_ERROR;
}

int ss_cmd_checkchan( const CmdParams *cmdparams )
{
	Channel *c;
	BotInfo *nickname = NULL;
	lnode_t *lnode;
	Client *cm;
	
	SET_SEGV_LOCATION();
	c = FindChannel( cmdparams->av[0] );
	if( c == NULL )
	{
		irc_prefmsg( ss_bot, cmdparams->source, "Can not find Channel %s, It has to have Some Users!", cmdparams->av[0] );
		return NS_SUCCESS;
	}			
	/* first, run the channel through the viri list, make sure its not bad */
	/* now scan channel members */
	lnode = list_first( c->members );
	while( lnode )
	{
		cm = FindUser( lnode_get( lnode ) );
		if( cm && ScanChannelName( cm, c ) == 0 )
		{
			/* if its 0, means its ok, no need to scan other members */
			break;
		}
		lnode = list_next( c->members, lnode );
	}
	nickname = GetNewBot( 0 );
	if( nickname ==NULL )
	{
		irc_prefmsg( ss_bot, cmdparams->source, "Couldnt Find a free Nickname to check %s with. Giving up( Try again later )", cmdparams->av[0] );
		return NS_SUCCESS;
	}
	/* first, if the lastchan and last nick are not empty, it means one of our bots is in a chan, sign them off */
	if( lastchan[0] != 0 )
	{
		irc_part( ojbotptr, lastchan, NULL );
		irc_quit( ojbotptr, "Finished Scanning" );
		ojbotptr = NULL;
	}
	strlcpy( lastnick, nickname->nick, MAXNICK );
	strlcpy( lastchan, c->name, MAXCHANLEN );
	/* ok, init the new bot. */
	ojbotptr = AddBot( nickname );
	if( ojbotptr == NULL )
	{
		lastchan[0] = 0;
		lastnick[0] = 0;
		return NS_SUCCESS;
	}
	irc_umode( ojbotptr, ojbotptr->u->name, UmodeStringToMask( onjoinbot_modes ) );
	irc_cloakhost( ojbotptr );
	irc_join( ojbotptr, c->name, 0 );
	irc_chanalert( ss_bot, "Scanning %s with %s for OnJoin Viruses by request of %s", c->name, nickname->nick, cmdparams->source->name );
	irc_prefmsg( ss_bot, cmdparams->source, "Scanning %s with %s", c->name, nickname->nick );
	return NS_SUCCESS;
}

int ss_cmd_monchan( const CmdParams *cmdparams )
{
	SET_SEGV_LOCATION();
	if( ircstrcasecmp( cmdparams->av[0], "ADD" )== 0 )
		return ss_cmd_monchan_add( cmdparams );
	if( ircstrcasecmp( cmdparams->av[0], "DEL" )== 0 )
		return ss_cmd_monchan_del( cmdparams );
	if( ircstrcasecmp( cmdparams->av[0], "LIST" )== 0 )
		return ss_cmd_monchan_list( cmdparams );
	return NS_ERR_SYNTAX_ERROR;
}

int ss_cmd_cycle( const CmdParams *cmdparams )
{
	SET_SEGV_LOCATION();
	cycle_onjoin_chan();
	return NS_SUCCESS;
}

int ss_cmd_set_monbot( const CmdParams *cmdparams, SET_REASON reason )
{
	/* this is ok, its just to shut up fussy compilers */
	BotInfo *nickname = NULL;
	lnode_t *rnn;

	SET_SEGV_LOCATION();
	switch( reason )
	{
		case SET_LOAD:
			DBAFetchConfigStr( "MonBot", SecureServ.monbot, MAXNICK );
			break;
		case SET_LIST:
			irc_prefmsg( ss_bot, cmdparams->source, "MONBOT:       %s",( strlen( SecureServ.monbot ) > 0 ) ? SecureServ.monbot : "Not Set" );
			break;
		case SET_CHANGE:
			/* Do not allow overwrite of the monbot if one is assigned and active */
			if( SecureServ.monbot[0] != 0 && list_count( monchans ) > 1 )
			{
				irc_prefmsg( ss_bot, cmdparams->source, "Monitor bot already set to %s and is monitoring channels.", SecureServ.monbot );
				return NS_SUCCESS;
			}
			/* don't allow a monitor bot to be assigned if we don't have enough onjoin bots */
			if( list_count( nicks ) <= 2 )
			{
				irc_prefmsg( ss_bot, cmdparams->source, "Not enough Onjoin bots would be left if you assign a MonBot. Please create more Onjoin Bots" );
				return NS_SUCCESS;
			}
			rnn = list_first( nicks );
			while( rnn != NULL )
			{
				nickname = lnode_get( rnn );
				if( ircstrcasecmp( nickname->nick, cmdparams->av[1] )== 0 )
				{
					/* ok, got the bot ! */
					break;
				}
				rnn = list_next( nicks, rnn );
			}
			if( nickname != NULL )
			{
				/* Do not allow monbot to be assigned if its online as a Onjoin bot atm */
				if( FindUser( nickname->nick ) )
				{
					irc_prefmsg( ss_bot, cmdparams->source, "Can't assign a monitor bot while it is online as a Onjoin Bot. Please try again in a couple of minutes" );
					return NS_SUCCESS;
				}
				strlcpy( SecureServ.monbot, nickname->nick, MAXNICK );
				DBAStoreConfigStr( "MonBot", SecureServ.monbot, MAXNICK );
				irc_prefmsg( ss_bot, cmdparams->source, "Monitoring bot set to %s", cmdparams->av[1] );
				CommandReport( ss_bot, "%s set the monitor bot to %s", cmdparams->source->name, cmdparams->av[1] );
				return NS_SUCCESS;
			}
			irc_prefmsg( ss_bot, cmdparams->source, "Can't find %s in bot list. /msg %s bot list for Bot List", cmdparams->av[1], ss_bot->name );
			break;
		default:
			break;
	}
	return NS_SUCCESS;
}

int CheckMonBotKill( const CmdParams *cmdparams )
{
	lnode_t *mcnode;
	char *chan;

	if( SecureServ.monbot[0] == 0 )
		return 0;
	if( monbotptr && cmdparams->bot != monbotptr )
		return 0;
	if( InitMonBot() == NS_TRUE )
	{
		mcnode = list_first( monchans );
		while( mcnode != NULL )
		{
			chan = lnode_get( mcnode );
			if( chan && FindChannel( chan ) )
			{
				irc_join( monbotptr, chan, 0 );
			}
			mcnode = list_next( monchans, mcnode );		
		}
	}
	return NS_TRUE;
}

int CheckOnJoinBotKill( const CmdParams *cmdparams )
{
	if (!ircstrcasecmp(cmdparams->target->name, lastnick))
	{
		lastnick[0] = '\0';
		return NS_TRUE;
	}
	return NS_FALSE;
}

int ss_event_emptychan( const CmdParams *cmdparams )
{
	if( monbotptr && cmdparams->bot == monbotptr )
	{
		irc_part( monbotptr, cmdparams->channel->name, NULL );
		return NS_SUCCESS;
	}
	if( ojbotptr && cmdparams->bot == ojbotptr )
	{
		irc_quit( ojbotptr, "Leaving" );
		ojbotptr = NULL;
		lastchan[0] = 0;
		lastnick[0] = 0;
	}
	return NS_SUCCESS;
}
