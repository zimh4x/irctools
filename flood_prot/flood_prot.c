/*
 * Allow only a definable number of messages per second to irc
 * to avoid excess flooding/sendQ.  We must register our handler
 * as LowLevel in order to get always get called before the actual
 * write() call to the socket.
 *
 * zz
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "won.h"

int proto_per_second=0;
int sleep_on_throttl=0;
uint32 throttle(WON_MODULE_CTX *modctx,WON_PACKET *packet)
{
	// don't throttle DCC and botnet connections here
	if (packet->type != WON_CONNECTION_IRC )
		return WON_STATUS_SUCCESS;
	static unsigned int t1=0,t2=0,mcount=0;
	mcount++;
	if ( t1==0 )
	{
		t1=(unsigned int)time(NULL);
		return WON_STATUS_SUCCESS;
	}
	t2 = (unsigned int)time(NULL);
	if ( (t2 > t1) && mcount >= proto_per_second )
	{
		wonLog( modctx->wonctx, modctx, "throttling %d seconds...", sleep_on_throttl );
		sleep(sleep_on_throttl);
		mcount=0;
	}
	// make sure t1 is always timestamp of last line sent
	t1=(unsigned int)time(NULL);
	return WON_STATUS_SUCCESS;
}


//set lines_per_second
uint32 setFloodRate(WON_CONFIG_PACKET *wcp)
{
	if ( wcp->buffer->words==1 )
	{
		fprintf(stderr, "flood_prot.so: lines_per_second missing an argument!\n");
		return WON_STATUS_FAILURE;
	}
	proto_per_second=atoi(wcp->buffer->str[1]);
	return WON_STATUS_SUCCESS;
}

//set sleep_on_throttl
uint32 setSleepTime(WON_CONFIG_PACKET *wcp)
{
	if ( wcp->buffer->words==1 )
	{
		fprintf(stderr, "flood_prot.so: sleep_flood missing an argument!|n");
		return WON_STATUS_FAILURE;
	}
	sleep_on_throttl = atoi(wcp->buffer->str[1]);
	return WON_STATUS_SUCCESS;
}



uint32 wonLoad(WON_MODULE_CTX *modctx)
{
	wonLog(modctx->wonctx, modctx, "flood_prot loading.");
	wonLowlevelSendRegisterLayeredHandler(modctx->wonctx, modctx, WON_LAYER_FIRST, throttle);
	wonConfigRegisterLayeredHandler(modctx->wonctx, modctx, WON_LAYER_LAST, "lines_per_second", setFloodRate );
	wonConfigRegisterLayeredHandler(modctx->wonctx, modctx, WON_LAYER_LAST, "sleep_on_flood", setSleepTime );

	// use defaults if no config data got loaded
	if ( proto_per_second == 0 )
		proto_per_second = 4;
	if ( sleep_on_throttl == 0 )
		sleep_on_throttl = 3;

	wonLog(modctx->wonctx, modctx, "loaded flood_prot.");
	return WON_STATUS_SUCCESS;
}

uint32 wonUnload(WON_MODULE_CTX *modctx)
{
	wonLog(modctx->wonctx, modctx, "flood_prot unloading.");
	wonLowlevelSendDeregisterLayeredHandler(modctx->wonctx, throttle );
	wonConfigDeregisterLayeredHandler(modctx->wonctx, modctx, "lines_per_second", setFloodRate );
	wonConfigDeregisterLayeredHandler(modctx->wonctx, modctx, "sleep_on_flood", setSleepTime );
	wonLog(modctx->wonctx, modctx, "flood_prot unloaded.");
	return WON_STATUS_SUCCESS;
}

// handle loading and saving config file
uint32 wonIoctl(WON_MODULE_CTX *modctx,uint32 ioctl, WON_IC *wic)
{
        switch (ioctl)
        {
                case WON_IOCTL_LOAD_COMPLETE:
                        if (proto_per_second == 0 || sleep_on_throttl == 0 )
                        {
                                wonLog(modctx->wonctx,modctx,"no flood_protection config settings...using defaults (4 lines per second, sleep 3 seconds on throttle)");
				proto_per_second = 4;
				sleep_on_throttl = 3;
                        }
                case WON_IOCTL_CONFIG_SAVE:
                        if ( proto_per_second > 0 && sleep_on_throttl > 0 )
                        {
                                FILE *fd = (FILE *)wic->inBuffer;

                                fprintf(fd,"# flood_prot.so configuration\n");
                                fprintf(fd,"lines_per_second %d\n", proto_per_second);
				fprintf(fd,"sleep_on_flood %d\n", sleep_on_throttl);

                        }
                        break;
        }

        return WON_STATUS_SUCCESS;
}
