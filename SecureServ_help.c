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
** $Id: SecureServ_help.c 400 2005-12-05 11:45:20Z Fish $
*/

#include "SecureServ.h"

const char *ts_help_login[] = {
	"Login as a helper",
	"Syntax: \2LOGIN <username> <password>\2",
	"",
	"This command allows Antivirus users to login to SecureServ",
	"By Logging into SecureServ, it allows SecureServ to notify",
	"you and direct any user infected with a Virus to the Help",
	"Channel",
	"",
	"SecureServ will monitor your availability, and if you set",
	"away, quit, or part the Help Channel, it will",
	"automatically log you out",
	"",
	"The username and password will be provided by the",
	"Network Administration",
	NULL
};

const char *ts_help_logout[] = {
	"Logout as a helper",
	"Syntax: \2LOGOUT\2",
	"",
	"This command logs you out of SecureServ's Antivirus Helper",
	"System. You should issue this command if you are logged in",
	"and are unable to provide any Antivirus help at this time.",
	NULL
};
const char *ts_help_chpass[] = {
	"Change your Helper Password",
	"Syntax: \2CHPASS <newpassword>\2",
	"",
	"This command changes your Helper Password.",
	"You must be logged into the SecureServ Helper System to use this command",
	NULL
};

const char *ts_help_checkchan[] = {
	"Scan a Channel",
	"Syntax: \2CHECKCHAN <channel>\2",
	"",
	"This option will scan a channel for Trojans. Use this if",
	"you suspect a channel contains Trojans",
	NULL
};

const char *ts_help_cycle[] = {
	"Scan next channel",
	"Syntax: \2CYCLE\2",
	"",
	"This option will force SecureServ to part the current",
	"channel it is checking and move onto the next random",
	"channel",
	NULL
};

const char *ts_help_update[] = {
	"Download latest definitions",
	"Syntax: \2UPDATE\2",
	"",
	"This option will force SecureServ to check the definitions",
	"file version and automatically update them to the latest",
	"version if required",
	"",
	"A valid username and password have to be set via the SET",
	"interface for this to function",
	NULL
};

const char *ts_help_list[] = {
	"Current list of virus definitions",
	"Syntax: \2LIST\2",
	"",
	"View detailed information about what SecureServ's",
	"definition database currently contains",
	NULL
};

const char *ts_help_monchan[] = {
	"Set channel monitor bot",
	"Syntax: \2MONCHAN LIST\2",
	"        \2MONCHAN ADD <channel>\2",
	"        \2MONCHAN DEL <channel>\2",
	"",
	"This command lets you assign a bot to stay in Specific",
	"channels to monitor for private message type viruses.",
	"You must specify a bot to use with",
	"/msg SecureServ set monbot <nick>",
	"See /msg SecureServ help set for more info",
	"",
	"\2LIST\2 will list the current channels that will be",
	"monitored. Should a channel listed here not exist when you", 
	"start SecureServ it will be automatically deleted from the",
	"list.",
	"\2ADD\2 will add an entry of <channel> to the list of",
	"monitored channels. The channel has to exist when you",
	"use this command.",
	"\2DEL\2 will delete the <channel> from the monitored",
	"channels list.",
	NULL
};

const char *ts_help_bots[] = {
	"Manage random Bot list",
	"Syntax: \2BOTS LIST\2",
	"        \2BOTS ADD <nick> <ident> <host> <info>\2",
	"        \2BOTS DEL <index>\2",
	"",
	"This command lets you view or manipulate the random Bot",
	"list. Bots from this list are randomly selected to join",
	"channels, scanning for on join based viruses",
	"You should try to use names/hosts etc that look real, and",
	"if possible, should change this list often.",
	"",
	"\2LIST\2 will list the current bots together with an",
	"ID number for use in removing entries.",
	"",
	"\2ADD\2 will add an entry with these details to the bot",
	"list.",
	"",
	"\2DEL\2 will delete entry <index> from the list.",
	"Use the LIST command to find the index.",
	NULL
};

const char *ts_help_helpers[] = {
	"Manage helper list",
	"Syntax: \2HELPERS LIST\2",
	"        \2HELPERS ADD <username> <password>\2",
	"        \2HELPERS DEL <username>\2",
	"",
	"Allows you to view or manipulate the helpers list.",
	"Helpers can be normal users that maintain your antivirus", 
	"channels and can help users with virus infections.",
	"Helpers have special privileges that allow them to kill",
	"infected users, or release users after the user has been",
	"identified as an infected user",
	"",
	"\2LIST\2 will list the current helpers. If a",
	"nickname is listed after the username, they are",
	"currently logged in.",
	"\2ADD\2 will add a helper entry with the username",
	"and password provided.",
	"\2DEL\2 will delete the helper entry with the",
	"username provided.",
	NULL
};


const char *ts_help_status[] = {
	"Current Status of SecureServ",
	"Syntax: \2STATUS\2",
	"",
	"Provide you with the current status of SecureServ.",
	NULL
};

const char *ts_help_assist[] = {
	"Release/Akill infected user",
	"Syntax: \2ASSIST RELEASE <target>\2",
	"        \2ASSIST KILL <target>\2",
	"",
	"Allows Helpers to Release or akill infected users that",
	"have been joined to the help channel",
	"This command is only available to Helpers while logged in",
	"\2RELEASE\2 will releases SecureServ's hold on",
	"<target> so that they may rejoin channels",
	"\2KILL\2 will kill <target> from the network.",
	"Should only be used when the helper",
	"is unable to clean/help the user",
	NULL
};

const char *ts_help_reload[] = {
	"Reload virus defintions",
	"Syntax: \2RELOAD\2",
	"",
	"Force SecureServ to reload the virus definition files.",
	"Used after manual updates to viri.dat or customviri.dat.",
	NULL
};

const char *ts_help_set_updateuser[] = {
	"\2UPDATEUSER <username>\2",
	"User name for updating the SecureServ definitions file.",
	"See the Readme file for more info",
	NULL
};

const char *ts_help_set_updatepass[] = {
	"\2UPDATEPASS <password>\2",
	"Password for updating the SecureServ definitions file.",
	"See the Readme file for more info",
	NULL
};

const char *ts_help_set_helpers[] = {
	"\2HELPERS <ON|OFF>\2",
	"Whether to enable the helper system for infected users",
	NULL
};

const char *ts_help_set_version[] = {
	"\2VERSION <ON|OFF>\2",
	"Whether to use CTCP version checking",
	NULL
};
const char *ts_help_set_signonmsg[] = {
	"\2SIGNONMSG <message>\2",
	"Message sent to users when they connect and CTCP version checking is enabled",
	NULL
};
const char *ts_help_set_botquitmsg[] = {
	"\2BOTQUITMSG <message>\2",
	"Message sent when onjoin bots quit",
	NULL
};
const char *ts_help_set_akillmsg[] = {
	"\2AKILLMSG <message>\2",
	"Message sent to users when they are akilled",
	NULL
};
const char *ts_help_set_nohelpmsg[] = {
	"\2NOHELPMSG <message>\2",
	"Message sent to users when there are no helpers logged in",
	NULL
};
const char *ts_help_set_helpchan[] = {
	"\2HELPCHAN <channel>\2",
	"Set the channel that infected users are joined to if there are helpers logged in",
	NULL
};
const char *ts_help_set_autosignout[] = {
	"\2AUTOSIGNOUT <ON|OFF>\2",
	"Automatically sign out helpers if they set away.",
	NULL
};
const char *ts_help_set_joinhelpchan[] = {
	"\2JOINHELPCHAN <ON|OFF>\2",
	"Whether SecureServ joins the help channel when there is at least one helper logged in",
	NULL
};
const char *ts_help_set_report[] = {
	"\2REPORT <ON|OFF>\2",
	"Enable Reporting to Secure.irc-chat.net of infected users.",
	NULL
};
const char *ts_help_set_doprivchan[] = {
	"\2DOPRIVCHAN <ON|OFF>\2",
	"Whether onjoin bots scan private channels",
	NULL
};
const char *ts_help_set_checkfizzer[] = {
	"\2CHECKFIZZER <ON|OFF>\2",
	"Enable Fizzer Checking. Only required if your network is affected by Fizzer",
	NULL
};
const char *ts_help_set_multicheck[] = {
	"\2MULTICHECK <ON|OFF>\2",
	"Makes SecureServ check all patterns when an infected user is found.",
	"Please read the Readme file for important performance information",
	NULL
};
const char *ts_help_set_akill[] = {
	"\2AKILL <ON|OFF>\2",
	"Whether SecureServ will akill or send a warning message to operators",
	NULL
};
const char *ts_help_set_akilltime[] = {
	"\2AKILLTIME <seconds>\2",
	"Time an AKILL will last for.",
	NULL
};
const char *ts_help_set_dojoin[] = {
	"\2SVSJOIN <ON|OFF>\2",
	"Whether SecureServ will issue a SVSJOIN. If disabled, the user is akilled instead",
	NULL
};
const char *ts_help_set_doonjoin[] = {
	"\2DOONJOIN <ON|OFF>\2",
	"Whether to do on join virus checking.",
	NULL
};
const char *ts_help_set_botecho[] = {
	"\2BOTECHO <ON|OFF>\2",
	"Make the onjoin bots echo messages received to the services channel regardless of the verbose setting",
	NULL
};
const char *ts_help_set_verbose[] = {
	"\2VERBOSE <ON|OFF>\2",
	"Enable verbose mode. Prepare to be flooded!",
	NULL
};
const char *ts_help_set_monchancycle[] = {
	"\2MONCHANCYCLE <ON|OFF>\2",
	"Should the monitor bot cycle the channels occasionally",
	NULL
};
#ifdef TREATCHANMSGASPM
const char *ts_help_set_treatchanmsgaspm[] = {
	"\2TREATCHANMSGASPM <ON|OFF>\2",
	"Make SecureServ check all channel messages against the virus signatures listed only for PM",
	"This option will consume \2LOTS\2 of CPU time. You shouldn't need to enable this under normal",
	"circumstances as the virus database has a seperate list of signatures for channels",
	NULL
};
#endif /* TREATCHANMSGASPM */ 
const char *ts_help_set_monchancycletime[] = {
	"\2MONCHANCYCLETIME <seconds>\2 ",
	"How often the monitor bot cycles a single channel",
	NULL
};
const char *ts_help_set_cycletime[] = {
	"\2CYCLETIME <seconds>\2",
	"How often SecureServ checks new channels for infections.",
	"See the Readme file for recommended settings",
	NULL
};
const char *ts_help_set_monbot[] = {
	"\2MONBOT <bot>\2",
	"Assign <bot> (from /msg SecureServ bots list) used for channel monitoring",
	NULL
};
const char *ts_help_set_autoupdate[] = {
	"\2AUTOUPDATE <ON|OFF>\2",
	"Should SecureServ automatically update the definitions file daily, if required?",
	NULL
};
const char *ts_help_set_autoupdatetime[] = {
	"\2AUTOUPDATETIME <seconds>\2",
	"How often SecureServ automatically checks for update if AUTOUPDATE is enabled",
	"Min - 3600 (1 Hour) , MAX - 172800 (2 days) , Default is 7200 seconds (2 hours)",
	NULL
};
const char *ts_help_set_onjoinbotmodes[] = {
	"\2ONJOINBOTMODES <modes>\2",
	"Modes used by onjoin bots. <modes> should be a valid mode string as used on",
	"IRC, e.g. -x. We recommend that this option is not used.",
	NULL
};
const char *ts_help_set_exclusions[] = {
	"\2EXCLUSIONS <ON|OFF>\2",
	"Use global exclusion list in addition to local exclusion list",
	NULL
};
