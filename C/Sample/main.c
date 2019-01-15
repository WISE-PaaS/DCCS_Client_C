#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dccsSDK.h"

#ifdef WIN32_CRTDBG
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h> 
#endif

void RecvMsgCB(int Msglen, const void *Msg)
{
	char *szMsg = NULL;

	szMsg = (char*)Msg;
	printf("%s\n", szMsg);

	return;
}

int main()
{
	const char *pszPublishTopic = NULL;
	const char *pszSubscribeTopic = NULL;
	int iRet = 0;
	DCCS_Handle dccsContent = NULL;
	
	//dccsContent = dccsSDK_lib_init("9fdb4d6b75eadd6a10663186dcd4534d");//Initial DCCS SDK. Input Your Service Key Name
	dccsContent = dccsSDK_lib_initWithDCCSURL("9fdb4d6b75eadd6a10663186dcd4534d", "https", "api-dccs-develop.iii-cflab.com", "/v1/serviceCredentials/", NULL);//Initial DCCS SDK. Input Your Service Key Name, DCCS Service Portocol, DCCS Service Host, DCCS Service Path

	pszPublishTopic = dccsSDK_lib_getAllowPublishTopic(dccsContent, &iRet);//Get Allow Publish Topic(Not Must)
	if (iRet == DCCS_GET_ALLOW_TOPIC_NO_LIMIT)
		printf("Get Publish Topic No Limit...\n");
	else if (iRet == DCCS_GET_ALLOW_TOPIC_LIMITED)
		printf("Get Publish Topic Limited...\n");
	else
		printf("Get Publish Topic Fail!!! Error Code = %d\n", iRet);
	
	pszSubscribeTopic = dccsSDK_lib_getAllowSubscribeTopic(dccsContent, NULL);//Get Allow Subscribe Topic(Not Must)
	if (iRet == DCCS_GET_ALLOW_TOPIC_NO_LIMIT)
		printf("Get Subscribe Topic No Limit...\n");
	else if (iRet == DCCS_GET_ALLOW_TOPIC_LIMITED)
		printf("Get Subscribe Topic Limited...\n");
	else
		printf("Get Subscribe Topic Fail!!! Error Code = %d\n", iRet);

	//dccsSDK_lib_publish(dccsContent, "/III/dccsTest/Test1", strlen("Hello_III_withSSL"), "Hello_III_withSSL", 0, 1);//Input your Publish Topic & Message Size & Message Content & Qos = 0, with SSL

	dccsSDK_lib_publish(dccsContent, "/III/dccsTest/Test1", strlen("Hello_III"), "Hello_III", 0, 0);//Input your Publish Topic & Message Size & Message Content & Qos = 0
	
	dccsSDK_lib_subscribe(dccsContent, "/III/dccsTest/Test1", 0, 1, RecvMsgCB);//Input your Subscribe Topic & Recv Message callback function& Qos

	dccsSDK_lib_cleanup(dccsContent);//Close DCCS SDK. Release Resource

#ifdef WIN32_CRTDBG 
	_CrtDumpMemoryLeaks(); 
#endif

	return 0;
}