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
** $Id: update.c 401 2005-12-11 05:28:04Z Fish $
*/

#include "SecureServ.h"
#include "updates.h"

/* update state type */
typedef enum UPDATE_STATE
{
	UPDATE_STATE_IDLE = 0,
	UPDATE_STATE_VERSION,
	UPDATE_STATE_DATA
} UPDATE_STATE;

/* update state flag */
static UPDATE_STATE updatestate = UPDATE_STATE_IDLE;
/* update temporary buffer */
static char ss_buf[SS_BUF_SIZE];

/** @brief downloaderror
 *
 *  list of possible errors for dat file updates
 *
 *  @param errcode ????
 *
 *  @return error string
 */

static const char *downloaderror( int errcode )
{
	switch( errcode )
	{
		case -1:
			return "Invalid username or password.";
		case -2:
			return "Account disabled. Please contact admin@lists.neostats.net";
		case -3:
			return "Your copy of SecureServ is too old. Please upgrade";
		default:
			break;
	}
	return "Unknown reason.";
}

/** @brief datdownload
 *
 *  downloads a dat file and loads the new version into memory if required 
 *
 *  @param unuseddata ????
 *  @param status ????
 *  @param data ????
 *  @param datasize ????
 *
 *  @return none
 */

static void datdownload( void *unuseddata, int status, char *data, int datasize ) 
{
	char tmpname[32];
	char *tmp, *tmp1;
	int i;
	
	SET_SEGV_LOCATION();
	/* if this is an automatic download, clear status */
	if( updatestate == UPDATE_STATE_DATA )
		updatestate = UPDATE_STATE_IDLE;
	if( status != NS_SUCCESS )
	{
		dlog( DEBUG1, "Virus definition download failed. %s", data );
		irc_chanalert( ss_bot, "Virus definition download failed. %s", data );
		return;
	}
	/* check response code */
	tmp = ns_malloc( datasize );
	strlcpy( tmp, data, datasize );
	tmp1 = tmp;
	i = atoi( strtok( tmp, "\n" ) );
	ns_free( tmp1 );	
	if( i <= 0 ) {
		nlog( LOG_NORMAL, "Permission denied trying to download Dat file: %d", i );
		irc_chanalert( ss_bot, "Permission denied trying to download Dat file: %d", i );
		return;
	}	
	/* make a temp file and write the contents to it */
	strlcpy( tmpname, "viriXXXXXX", 32 );
	os_write_temp_file( tmpname, data, datasize );
	/* rename the file to the datfile */
	os_rename( tmpname, VIRI_DAT_NAME );
	/* reload the dat file */
 	load_dat();
	nlog( LOG_NOTICE, "Dat file version %d has been downloaded and installed", SecureServ.datfileversion );
	irc_chanalert( ss_bot, "Dat file version %d has been downloaded and installed", SecureServ.datfileversion );
}
	
/** @brief DownLoadDat
 *
 *  
 *
 *  @param none
 *
 *  @return none
 */

static void DownLoadDat( void )
{
	SET_SEGV_LOCATION();
	/* dont keep trying to download !*/
	if( updatestate == UPDATE_STATE_VERSION )
	{
		updatestate = UPDATE_STATE_DATA;
		os_memset( ss_buf, 0, SS_BUF_SIZE );
		ircsnprintf( ss_buf, SS_BUF_SIZE, "u=%s&p=%s", MQUsername(), MQPassword());
		if( new_transfer( "http://secure.irc-chat.net/defs.php", ss_buf, NS_MEMORY, "", NULL, datdownload ) != NS_SUCCESS )
		{
			nlog( LOG_WARNING, "Definition download failed." );
			irc_chanalert( ss_bot, "Definition download failed. Check log files" );
		}	
	} 
}

/** @brief datdownload
 *
 *  automatic dat file updater callback function. Checks whats on the website 
 *  with whats local, and if website is higher, either prompts for an upgrade, 
 *  or does an automatic one : ) It just compares version numbers of the dat 
 *  file, and if they are different, starts a new download. 
 *
 *  @param data ????
 *  @param status ????
 *  @param ver ????
 *  @param versize ????
 *
 *  @return none
 */

static void datver( void *data, int status, char *ver, int versize ) 
{
	int myversion;
	Client *u =( void * )data;
	
	SET_SEGV_LOCATION();
	/* check there was no error */
	if( status == NS_SUCCESS ) {
		myversion = atoi( ver );
		if( myversion <= 0 ) {
			nlog( LOG_WARNING, "Permission Denied trying to check Dat file version: %s", downloaderror( myversion ) );
			irc_chanalert( ss_bot, "Permission Denied trying to check Dat file version: %s", downloaderror( myversion ) );
			if( u ) irc_prefmsg( ss_bot, u, "Permission Denied trying to check Dat file version: %s", downloaderror( myversion ) );
			return;
		}			
		dlog( DEBUG1, "LocalDat Version %d, WebSite %d", SecureServ.datfileversion, myversion );
		if( myversion > SecureServ.datfileversion ) {
			if( SecureServ.autoupgrade > 0 || u ) {
				updatestate = UPDATE_STATE_VERSION;
				DownLoadDat();
				if( u ) irc_prefmsg( ss_bot, u, "A new Dat file version %d is being downloaded. Please Monitor the Services Channel", myversion );
			 } else {
				irc_chanalert( ss_bot, "A new Dat file version %d is available. You should /msg %s update", myversion, ss_bot->name );
				/* no need to send a prefmsg to a nick here as in most cases, this is probabably triggered by a timer */
			 }
		} else {
				irc_chanalert( ss_bot, "SecureServ is operating with the most recent Dat file. No update required." );
				if( u ) irc_prefmsg( ss_bot, u, "SecureServ is operating with the most recent Dat file. No update required." );
		}
	} else {
		nlog( LOG_WARNING, "Virus definition check failed. %s", ver );
		irc_chanalert( ss_bot, "Virus definition check failed: %s", ver );
		if( u ) irc_prefmsg( ss_bot, u, "Virus definition check failed. %s", ver );
		return;
	}
}

/** @brief AutoUpdate
 *
 *  UPDATE timer handler
 *
 *  @param ????
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

int AutoUpdate( void *userptr )
{
	SET_SEGV_LOCATION();
	if( ( SecureServ.autoupgrade > 0 ) && (MQCredOk() == NS_SUCCESS)) {
		os_memset( ss_buf, 0, SS_BUF_SIZE );
		ircsnprintf( ss_buf, SS_BUF_SIZE, "u=%s&p=%s", MQUsername(), MQPassword());
		if( new_transfer( "http://secure.irc-chat.net/vers.php", ss_buf, NS_MEMORY, "", NULL, datver ) != NS_SUCCESS ) {
			nlog( LOG_WARNING, "Definition version check failed." );
			irc_chanalert( ss_bot, "Definition version check failed. Check log files" );
		}	
	}
	return NS_SUCCESS;
}	

/** @brief ss_cmd_update
 *
 *  UPDATE command handler
 *
 *  @param cmdparam struct
 *
 *  @return NS_SUCCESS if suceeds else result of command
 */

int ss_cmd_update( const CmdParams *cmdparams )
{
	SET_SEGV_LOCATION();
	os_memset( ss_buf, 0, SS_BUF_SIZE );
	if (MQCredOk() != NS_SUCCESS) {
		irc_prefmsg( ss_bot, cmdparams->source, "A NeoNet Username/Password has not been set. Update Failed");
		return NS_FAILURE;
	}
	ircsnprintf( ss_buf, SS_BUF_SIZE, "u=%s&p=%s", MQUsername(), MQPassword());
	if( new_transfer( "http://secure.irc-chat.net/vers.php", ss_buf, NS_MEMORY, "", cmdparams->source, datver ) != NS_SUCCESS ) {
		irc_prefmsg( ss_bot, cmdparams->source, "Definition Download Failed. Check Log Files" );
		nlog( LOG_WARNING, "Definition Download failed." );
		irc_chanalert( ss_bot, "Definition Download failed. Check log files" );
		return NS_FAILURE;
	}	
	irc_prefmsg( ss_bot, cmdparams->source, "Requesting New Dat File." );
	irc_chanalert( ss_bot, "%s requested an update to the Dat file", cmdparams->source->name );
	return NS_SUCCESS;
}

/** @brief ss_cmd_set_autoupdate_cb
 *
 *  Set callback for set autoupdate
 *  validate autoupdate setting
 *
 *  @params cmdparams pointer to commands param struct
 *  @params reason for SET
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

int ss_cmd_set_autoupdate_cb( const CmdParams *cmdparams, SET_REASON reason ) 
{
	switch( reason )
	{
		case SET_VALIDATE:
			if (MQCredOk() != NS_SUCCESS) {
				irc_prefmsg( ss_bot, cmdparams->source, "You can not enable AutoUpdate without setting the NeoNet Username/Password Combination" );
				return NS_FAILURE;
			}
			break;
		case SET_CHANGE:
			if( SecureServ.autoupgrade == 1 ) 
			{
				AddTimer( TIMER_TYPE_INTERVAL, AutoUpdate, "AutoUpdate", SecureServ.autoupgradetime, NULL );
			} 
			else 
			{
				DelTimer( "AutoUpdate" );
			}
			break;
		default:
			break;
	}
	return NS_SUCCESS;
}

/** @brief ss_cmd_set_autoupdatetime_cb
 *
 *  Set callback for set autoupdatetime
 *  Adjust timer interval
 *
 *  @params cmdparams pointer to commands param struct
 *  @params reason for SET
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

int ss_cmd_set_autoupdatetime_cb( const CmdParams *cmdparams, SET_REASON reason ) 
{
	if( reason == SET_CHANGE )
	{
		if( ( SecureServ.autoupgrade == 1 ) &&( MQCredOk() == NS_SUCCESS ) ) 
			SetTimerInterval( "AutoUpdate", SecureServ.autoupgradetime );
	}
	return NS_SUCCESS;
}
