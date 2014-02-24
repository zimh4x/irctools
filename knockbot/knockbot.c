/*
 * make wonton /invite users who /quote KNOCK #somechan
 * provided they are a valid bot users with a matching hostmask
 * and the channel is found in their channel list.
 *
 * zz
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "won.h"

typedef struct _wonknrl_network {
        char            *name;                  /* Network name         */
        char            *nickname;              /* Primary nickname     */
        void            *currentChannel;        /* Current channel      */
        void            *currentUser;           /* Current user         */

        unsigned long   vhost;                  /* Vhost addr           */

        char            *versionReply;          /* Version reply        */
        char            *realname;              /* realname             */
        char            *gecosReply;            /* GECOS reply          */
        char            *dccUserPrompt;
        char            *dccPassPrompt;
        char            *motdFile;

        LINKED_LIST     channels;
        LINKED_LIST     servers;                /* Servers              */
        LINKED_LIST     users;                  /* Users                */
} WONKRNL_NETWORK;

typedef struct _wonkrnl_channel {
        WONKRNL_NETWORK *network;

        unsigned int    state;

        char            *channel;
        char            *key;

        LINKED_LIST     bans;                   /* Bans                 */
} WONKRNL_CHANNEL;

typedef struct _wonkrnl_user {
        WONKRNL_NETWORK *network;

        char            *username;              /* Username             */
        unsigned char   password[64];           /* sha2 password digest */
        unsigned int    gaccess;                /* global access        */

        LINKED_LIST     channels;               /* channel access list  */
        LINKED_LIST     hosts;                  /* hosts                */
} WONKRNL_USER;

typedef struct _wonkrnl_user_channel {
        WONKRNL_USER    *user;
        WONKRNL_CHANNEL *channel;

        unsigned int    access;
} WONKRNL_USER_CHANNEL;

/* 710 RPL_KNOCK	":%s 710 %s %s %s!%s@%s :has asked for an invite." */

uint32 ircKnockMsg( WON_IRC_PACKET* wip );

uint32 ircKnockMsg( WON_IRC_PACKET* wip ) /* 710	1 */
{
	/* 10 words...
	 * [0] :irc.server.com
	 * [1] 710
	 * [2] #somechan
	 * [3] #somechan (again?)
	 * [4] nick!user@host
	 */
	if ( wip->buffer->words != 10 )
		return WON_STATUS_SUCCESS;
	WONKRNL_USER* botuser; 
	WONKRNL_USER_CHANNEL* userchan;
	WONKRNL_NETWORK *ircnet = (WONKRNL_NETWORK*)wip->irc->ircExtension;
	LINKED_LIST_ITEM *item, *hostItem;

        item = listGetFirstItem( &ircnet->users );
	while ( item && item->value )
	{
		botuser = (WONKRNL_USER* )item->value;
		hostItem = listGetFirstItem( &botuser->hosts );
		while ( hostItem && hostItem->value )
		{
			if (wonWildcardMatch( (unsigned char* )hostItem->value, wip->buffer->str[4] ) )
			{
				/* found a bot user for hostmask of client who requested invite */
				userchan = (WONKRNL_USER_CHANNEL *)listGetValueStringId(&botuser->channels,(char *)wip->buffer->str[2] );
				if ( userchan )
				{
					/* user who matches by hostmask is added for channel axxs */
					if ( wonWildcardMatch( "*!*@*",wip->buffer->str[4] ) )
					{
						int copySize = (strchr(wip->buffer->str[4],'!')) - (wip->buffer->str[4]);
						char* fromnick = wonMemoryAllocate( WON_MAX_NICKNAME_SIZE, 1 );
						strncpy( fromnick, wip->buffer->str[4], (copySize > WON_MAX_NICKNAME_SIZE-1)?WON_MAX_NICKNAME_SIZE:copySize);
						wonIrcSend( wip->ctx, wip->irc, "INVITE %s %s\n", fromnick, userchan->channel->channel );
						wonDccSendAll( wip->ctx, "Sent invite to %s @ %s for %s\n", 
											userchan->user->username, wip->buffer->str[4], userchan->channel->channel );
						wonMemoryFree(fromnick);
						return WON_STATUS_SUCCESS;
					}
					else
					{
						/* for some reason wip->buffer->str[4] is not a hostmask? */
						wonDccSendAll( wip->ctx, "Handler FAILED for 710 msg.  wtf nucca?!\n" );
						return WON_STATUS_SUCCESS;
					}
				}
				/* didnt find channel in user's channel list */
				wonDccSendAll( wip->ctx, "Bot user %s requested invite to %s without access\n", botuser->username, wip->buffer->str[2] );
				wonLog( wip->ctx, wip->modctx, "Bot user %s requested invite to %s without access", botuser->username, wip->buffer->str[2] );
				return WON_STATUS_SUCCESS;
			}
			hostItem=listGetNextItem(hostItem); /* next hostmask in bot user's list */

		}
		item=listGetNextItem(item); /* next bot username in list */
		
	}
	wonDccSendAll( wip->ctx, "Client %s requested invite to %s without access from that hostmask\n", wip->buffer->str[4], wip->buffer->str[2] );
	wonLog( wip->ctx, wip->modctx, "Client %s requested invite to %s without access from that hostmask", wip->buffer->str[4], wip->buffer->str[2] );
	return WON_STATUS_SUCCESS;
}

void wonLoad(WON_MODULE_CTX *modctx)
{
	wonLog(modctx->wonctx, modctx, "knockbot loading.");
	wonIrcRegisterLayeredHandler(modctx->wonctx, modctx, WON_LAYER_FIRST, "710", 1, ircKnockMsg);
	wonLog(modctx->wonctx, modctx, "loaded knockbot.");
}

void wonUnload(WON_MODULE_CTX *modctx)
{
	wonLog(modctx->wonctx, modctx, "knockbot unloading.");
	wonIrcDeregisterLayeredHandler(modctx->wonctx, modctx, "710", 1, ircKnockMsg);
	wonLog(modctx->wonctx, modctx, "knockbot unloaded.");
}
