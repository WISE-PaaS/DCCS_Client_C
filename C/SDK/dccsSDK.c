#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#ifdef WIN32
	#include <ws2tcpip.h>
	#include <windows.h>
#else
	#include <unistd.h>
	#include <sys/socket.h>
	#include <sys/types.h>
	#include <netinet/in.h>
	#include <netinet/tcp.h>
	#include <netdb.h>
#endif
#include "jansson.h"
#include "mosquitto.h"
#include "openssl/ssl.h"

#include "dccsSDK.h"

#define DCCS_SERVICE_PORTOCOL "https" //"https" or "http"
#define DCCS_SERVICE_HOST "api-dccs-develop.iii-cflab.com"
#define DCCS_SERVICE_PATH "/v1/serviceCredentials/"

#define EQUAL 0
#define SSL_SUCCESS 1

#define MAXSTRINGSIZE 256

#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif
#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#ifdef WIN32_CRTDBG
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h> 
#endif

char g_DCCS_PORTOCOL[MAXSTRINGSIZE];
char g_DCCS_HOST[MAXSTRINGSIZE];
char g_DCCS_PATH[MAXSTRINGSIZE];

typedef struct dccsSDKwithSSL {
	char Username[MAXSTRINGSIZE];
	char Password[MAXSTRINGSIZE];
	int Port;
	char PSK[MAXSTRINGSIZE];
	char PSK_Identity[MAXSTRINGSIZE];
}dccsSDKwithSSL_t;

typedef struct dccsSDK {
	char Username[MAXSTRINGSIZE];
	char Password[MAXSTRINGSIZE];
	char BrokeHost[MAXSTRINGSIZE];
	int Port;
	char *ServiceKey;
	char *TopicSubscribe;
	char *TopicPublish;
	int RetryNum;
	dccsSDKwithSSL_t *SSLInfo;
	int withSSL;
}dccsSDK_t;

typedef struct connectContent {
	dccsSDK_t *dccsContent;
	char *Topic;
	int Payloadlen;
	const void *Payload;
	int Qos;
	int RetCode;
	int bIsPub;
	recvMsgCB CB_Func;
}connectContent_t;

#pragma comment(lib, "ws2_32.lib")

//MQTT client Func. (mosquitto)

char* mosquitto_getRandomId()
{
	int  r1, r2, r3;
	char szID[256];
	
	r1 = rand();// returns a pseudo-random integer between 0 and RAND_MAX
	r2 = rand();
	r3 = rand();

	memset(szID, 0, sizeof(szID));
	sprintf(szID, "%04d%04d%04d", r1%1000, r2%1000, r3%1000);

	return szID;
}

void mosquitto_connect_callback(struct mosquitto *mosq, void *obj, int iMosqRet)
{
	connectContent_t *connectInfo = NULL;
	int iDCCSRet = 0;

	connectInfo = (connectContent_t*)obj;

	if (iMosqRet != 0)
	{
		if (iMosqRet == 4 && connectInfo->dccsContent->RetryNum == 0)//4: username or password worng;
		{
			connectInfo->dccsContent->RetryNum++;
			iDCCSRet = dccs_checkMQTTConnectInfo(connectInfo->dccsContent);
			if (iDCCSRet != DCCS_SUCCESS)
			{
				connectInfo->RetCode = iDCCSRet;
				goto FUNC_EXIT;
			}

			if (connectInfo->dccsContent->withSSL == TRUE)
			{
				mosquitto_tls_psk_set(mosq, connectInfo->dccsContent->SSLInfo->PSK, connectInfo->dccsContent->SSLInfo->PSK_Identity, NULL);
				mosquitto_username_pw_set(mosq, connectInfo->dccsContent->SSLInfo->Username, connectInfo->dccsContent->SSLInfo->Password);
				iMosqRet = mosquitto_connect(mosq, connectInfo->dccsContent->BrokeHost, connectInfo->dccsContent->SSLInfo->Port, 30);
			}
			else
			{
				mosquitto_username_pw_set(mosq, connectInfo->dccsContent->Username, connectInfo->dccsContent->Password);
				iMosqRet = mosquitto_connect(mosq, connectInfo->dccsContent->BrokeHost, connectInfo->dccsContent->Port, 30);
			}
			return;
		}
		else if (iMosqRet == 4)
		{
			connectInfo->dccsContent->RetryNum++;
			connectInfo->RetCode = DCCS_ERR_CREDENTIAL;
			goto FUNC_EXIT;
		}
		else
		{
			connectInfo->dccsContent->RetryNum++;
			connectInfo->RetCode = DCCS_ERR_INTERNAL_ERROR;
			goto FUNC_EXIT;
		}
	}

	if (connectInfo->bIsPub == TRUE)
	{
		//publish
		iMosqRet = mosquitto_publish(mosq, NULL, connectInfo->Topic, connectInfo->Payloadlen, connectInfo->Payload, connectInfo->Qos, 0);
	}
	else
	{
		//subscrib
		iMosqRet = mosquitto_subscribe(mosq, NULL, connectInfo->Topic, connectInfo->Qos);
	}
	connectInfo->dccsContent->RetryNum = 0;
	return;

FUNC_EXIT:
	mosquitto_disconnect(mosq);
	return;
}

void mosquitto_publish_callback(struct mosquitto *mosq, void *obj, int iMosqRet)
{
	mosquitto_disconnect(mosq);
}

void mosquitto_subscribe_callback(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
{
	return;
}

void mosquitto_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	connectContent_t *connectInfo = NULL;

	connectInfo = (connectContent_t*)obj;
	connectInfo->CB_Func(message->payloadlen, message->payload);

	return;
}
//=================================================================
#ifdef WIN32
	#define SOCKET_HANDLE SOCKET
#else
	#define SOCKET_HANDLE int
#endif

typedef struct getDCCSInfo
{
    int ReturnCode;
	char *Data;
}getDCCSInfo_t;

char* dccs_strtok(char* s, const char* delim, char** save_ptr)
{
	char* token;

	if (s == NULL)
		s = *save_ptr;

	/* Scan leading delimiters.  */
	s += strspn(s, delim);
	if (*s == '\0')
		return NULL;

	/* Find the end of the token.  */
	token = s;
	s = strpbrk(token, delim);
	if (s == NULL)
		/* This token finishes the string.  */
		*save_ptr = strchr(token, '\0');
	else {
		/* Terminate the token and make *SAVE_PTR point past it.  */
		*s = '\0';
		*save_ptr = s + 1;
	}
	return token;
}

int dccs_getCredential(char *ServiceKey, getDCCSInfo_t *dccsInfo)
{
	char szSendPackage[1024];
	char szRecvPackage[1024];
	struct addrinfo hints, *addrInfo;
	SOCKET_HANDLE sockfd;
	struct timeval tv_out;
	int iSendBytes, iRecvBytes, iTotalRecvSize;
	char *pszDot = NULL;
	int iTotalSize = 0;
	char szContentLen[MAXSTRINGSIZE];
	SSL *sslfd = NULL;
	SSL_CTX *sslctx = NULL;

#ifdef WIN32
	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2,2),&wsaData) != 0)
		return DCCS_ERR_UNKNOWN;
#endif
	
	memset(szSendPackage, 0, sizeof(szSendPackage));
	sprintf(szSendPackage, "GET %s%s HTTP/1.1\r\nHost: %s\r\n\r\n"
						  ,g_DCCS_PATH, ServiceKey, g_DCCS_HOST);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (strcmp(g_DCCS_PORTOCOL, "https") == EQUAL)
	{
		if (getaddrinfo(g_DCCS_HOST, "443", NULL, &addrInfo) != 0)
			return DCCS_ERR_INTERNET_ERROR;
	}
	else
	{
		if (getaddrinfo(g_DCCS_HOST, "80", NULL, &addrInfo) != 0)
			return DCCS_ERR_INTERNET_ERROR;
	}

	sockfd = socket(addrInfo->ai_family, addrInfo->ai_socktype, addrInfo->ai_protocol);
	if (sockfd == INVALID_SOCKET)
		return DCCS_ERR_INTERNET_ERROR;
		
	//set timeout
	memset(&tv_out, 0, sizeof(struct timeval));
#ifdef WIN32
	tv_out.tv_sec = 5 * 1000;
#else
	tv_out.tv_sec = 5;
#endif
	setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv_out, sizeof(tv_out));
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof(tv_out));

	if (connect(sockfd, addrInfo->ai_addr, addrInfo->ai_addrlen) == SOCKET_ERROR)
		return DCCS_ERR_INTERNET_ERROR;

	if (strcmp(g_DCCS_PORTOCOL, "https") == EQUAL)
	{
		OpenSSL_add_ssl_algorithms();
		SSL_load_error_strings();
		sslctx = SSL_CTX_new(TLSv1_2_client_method());
		if (sslctx == NULL)
			return DCCS_ERR_INTERNET_ERROR;
		SSL_CTX_set_verify(sslctx, SSL_VERIFY_NONE, NULL);
		if (SSL_CTX_set_trust(sslctx, TRUE) != SSL_SUCCESS)
			return DCCS_ERR_INTERNET_ERROR;

		sslfd = SSL_new(sslctx);                        
		if (sslfd == NULL)
			return DCCS_ERR_INTERNET_ERROR;
		if (SSL_set_fd(sslfd, sockfd) != SSL_SUCCESS)
			return DCCS_ERR_INTERNET_ERROR;
		if (SSL_connect(sslfd) != SSL_SUCCESS)
			return DCCS_ERR_INTERNET_ERROR;

		iSendBytes = SSL_write(sslfd, szSendPackage, strlen(szSendPackage));
	}
	else
	{
		iSendBytes = send(sockfd, szSendPackage, strlen(szSendPackage), 0);
	}
	if (iSendBytes != strlen(szSendPackage))
		return DCCS_ERR_INTERNET_ERROR;

	memset(szRecvPackage, 0, sizeof(szRecvPackage));

	if (strcmp(g_DCCS_PORTOCOL, "https") == EQUAL)
		iRecvBytes = SSL_read(sslfd, szRecvPackage, sizeof(szRecvPackage) - 1);
	else
		iRecvBytes = recv(sockfd, szRecvPackage, sizeof(szRecvPackage) - 1, 0);

	if (iRecvBytes <= 0)
		return DCCS_ERR_INTERNET_ERROR;

	//Check HTTP status code
	if (strncmp(szRecvPackage, "HTTP/1.1 200", 12) != 0)
	{
		char szStatusCode[4];

		memset(szStatusCode, 0, sizeof(szStatusCode));
		strncpy(szStatusCode, szRecvPackage + 9, 3);
		dccsInfo->ReturnCode = atoi(szStatusCode);
		return DCCS_ERR_INTERNET_ERROR;
	}
	else
		dccsInfo->ReturnCode = 200;

	pszDot = strstr(szRecvPackage, "Content-Length: ");
	if (pszDot == NULL)
		return DCCS_ERR_INTERNET_ERROR;

	pszDot = pszDot + 16;
	memset(szContentLen, 0, sizeof(szContentLen));
	strncpy(szContentLen, pszDot, strstr(pszDot, "\r\n") - pszDot);
	iTotalSize = atoi(szContentLen);

	dccsInfo->Data = (char*)malloc(iTotalSize + 16);
	memset(dccsInfo->Data, 0, iTotalSize + 16);

	pszDot = strstr(szRecvPackage, "\r\n\r\n");
	strcpy(dccsInfo->Data, pszDot + 4);
	iTotalRecvSize = strlen(dccsInfo->Data);

	while (iRecvBytes != SOCKET_ERROR && iRecvBytes > 0 && iTotalRecvSize < iTotalSize)
	{
		memset(szRecvPackage, 0, sizeof(szRecvPackage));
		
		if (strcmp(g_DCCS_PORTOCOL, "https") == EQUAL)
			iRecvBytes = SSL_read(sslfd, szRecvPackage, sizeof(szRecvPackage) - 1);
		else
			iRecvBytes = recv(sockfd, szRecvPackage, sizeof(szRecvPackage) - 1, 0);

		if (iRecvBytes <= 0)
			break;
		strcat(dccsInfo->Data, szRecvPackage);
		iTotalRecvSize += iRecvBytes;
	}

	return DCCS_SUCCESS;
}

int dccs_parseCredential(dccsSDK_t *dccsContent, char *Credential)
{
	int iReturn = DCCS_SUCCESS;
	json_error_t error;
	json_t *root;
	json_t *jObject = NULL;
	json_t *jValue = NULL;
	const char *pszValue = NULL;
	char szPort[16];
	
	json_set_alloc_funcs(malloc, free);
	root = json_loads(Credential, 0, &error);

	if (root == NULL)
	{
		iReturn = DCCS_ERR_INTERNAL_ERROR;
		goto FUNC_EXIT;
	}
	
	jValue = json_object_get(root, "serviceHost");
	if (jValue == NULL)
	{
		iReturn = DCCS_ERR_INTERNAL_ERROR;
		goto FUNC_EXIT;
	}
	strcpy(dccsContent->BrokeHost, json_string_value(jValue));

	//Parse Topic Start
	jObject = json_object_get(root, "serviceParameter");
	if (jObject == NULL)
	{
		iReturn = DCCS_ERR_INTERNAL_ERROR;
		goto FUNC_EXIT;
	}
	jValue = json_object_get(jObject, "rmqTopicRead");
	if (jValue != NULL)
	{
		pszValue = json_string_value(jValue);
		if (dccsContent->TopicSubscribe != NULL)
		{
			free(dccsContent->TopicSubscribe);
			dccsContent->TopicSubscribe = NULL;
		}
		if (strlen(pszValue) > 0)
			dccsContent->TopicSubscribe = strdup(pszValue);
	}
	jValue = json_object_get(jObject, "rmqTopicWrite");
	if (jValue != NULL)
	{
		pszValue = json_string_value(jValue);
		if (dccsContent->TopicPublish != NULL)
		{
			free(dccsContent->TopicPublish);
			dccsContent->TopicPublish = NULL;
		}
		if (strlen(pszValue) > 0)
			dccsContent->TopicPublish = strdup(pszValue);
	}
	//Parse Topic End

	jObject = json_object_get(root, "credential");
	jObject = json_object_get(jObject, "protocols");
	jObject = json_object_get(jObject, "mqtt");

	jValue = json_object_get(jObject, "username");
	if (jValue == NULL)
	{
		iReturn = DCCS_ERR_INTERNAL_ERROR;
		goto FUNC_EXIT;
	}
	strcpy(dccsContent->Username, json_string_value(jValue));

	jValue = json_object_get(jObject, "password");
	if (jValue == NULL)
	{
		iReturn = DCCS_ERR_INTERNAL_ERROR;
		goto FUNC_EXIT;
	}
	strcpy(dccsContent->Password, json_string_value(jValue));

	jValue = json_object_get(jObject, "port");
	if (jValue == NULL)
	{
		iReturn = DCCS_ERR_INTERNAL_ERROR;
		goto FUNC_EXIT;
	}
	dccsContent->Port = json_number_value(jValue);

	//Parse mqtt+ssl
	jObject = json_object_get(root, "credential");
	jObject = json_object_get(jObject, "protocols");
	jObject = json_object_get(jObject, "mqtt+ssl");
	if (jObject != NULL)
	{
		dccsContent->SSLInfo = (dccsSDKwithSSL_t*)malloc(sizeof(struct dccsSDKwithSSL));
		memset(dccsContent->SSLInfo, 0, sizeof(struct dccsSDKwithSSL));
		
		jValue = json_object_get(jObject, "username");
		if (jValue == NULL)
		{
			iReturn = DCCS_ERR_INTERNAL_ERROR;
			goto FUNC_EXIT;
		}
		strcpy(dccsContent->SSLInfo->Username, json_string_value(jValue));

		jValue = json_object_get(jObject, "password");
		if (jValue == NULL)
		{
			iReturn = DCCS_ERR_INTERNAL_ERROR;
			goto FUNC_EXIT;
		}
		strcpy(dccsContent->SSLInfo->Password, json_string_value(jValue));

		jValue = json_object_get(jObject, "port");
		if (jValue == NULL)
		{
			iReturn = DCCS_ERR_INTERNAL_ERROR;
			goto FUNC_EXIT;
		}
		dccsContent->SSLInfo->Port = json_number_value(jValue);
	}
	//Parse mqtt+ssl done...
	
FUNC_EXIT:
	json_decref(root);
	return iReturn;
}

int dccs_getMQTTConnectInfo(dccsSDK_t *dccsContent)
{
	int iReturn = DCCS_SUCCESS;
	getDCCSInfo_t *dccsInfo = NULL;

	dccsInfo = (struct getDCCSInfo*)malloc(sizeof(struct getDCCSInfo));
	memset(dccsInfo, 0, sizeof(struct getDCCSInfo));

	if (dccs_getCredential(dccsContent->ServiceKey, dccsInfo) != DCCS_SUCCESS)
	{
		if (dccsInfo->Data != NULL)
			free(dccsInfo->Data);
		if (dccsInfo->ReturnCode = 404)
			iReturn = DCCS_ERR_CREDENTIAL_NOT_FOUND;
		else if (dccsInfo->ReturnCode = 410)
			iReturn = DCCS_ERR_CREDENTIAL_GONE;
		else
			iReturn = DCCS_ERR_INTERNET_ERROR;

		free(dccsInfo);
		return iReturn;
	}

	iReturn = dccs_parseCredential(dccsContent, dccsInfo->Data);
	if (iReturn != DCCS_SUCCESS)
		return iReturn;

	free(dccsInfo->Data);
	free(dccsInfo);

	return iReturn;
}

int dccs_checkMQTTConnectInfo(dccsSDK_t *dccsContent)
{
	int iReturn = DCCS_SUCCESS;
	int max, min, result;

	if (dccsContent->RetryNum == 0 && strlen(dccsContent->BrokeHost) != 0 && strlen(dccsContent->Username) != 0 && strlen(dccsContent->Password) != 0)
		return DCCS_SUCCESS;

	if (dccsContent->RetryNum > 0)
	{
		min = (int)(pow(2, (double)(dccsContent->RetryNum + 1)));
		max = (int)(pow(2, (double)(dccsContent->RetryNum + 2)));
		srand((unsigned int)time(NULL));
		result = rand()%(max - min + 1) + min;

#ifdef WIN32
		Sleep(result * 1000);
#else
		sleep(result);
#endif
	}
		
	iReturn = dccs_getMQTTConnectInfo(dccsContent);

	return iReturn;
}

//=================================================================

libdccssdk_EXPORT DCCS_Handle dccsSDK_lib_init(char *ServiceKey)
{
	dccsSDK_t *dccsContent = NULL;

	if (ServiceKey == NULL)
		return NULL;

	memset(g_DCCS_PORTOCOL, 0, sizeof(g_DCCS_PORTOCOL));
	memset(g_DCCS_HOST, 0, sizeof(g_DCCS_HOST));
	memset(g_DCCS_PATH, 0, sizeof(g_DCCS_PATH));
	strcpy(g_DCCS_PORTOCOL, DCCS_SERVICE_PORTOCOL);
	strcpy(g_DCCS_HOST, DCCS_SERVICE_HOST);
	strcpy(g_DCCS_PATH, DCCS_SERVICE_PATH);

	dccsContent = (dccsSDK_t*)malloc(sizeof(dccsSDK_t));
	memset(dccsContent, 0, sizeof(dccsSDK_t));
	
	dccsContent->ServiceKey = strdup(ServiceKey);
	dccsContent->RetryNum = 0;

	return (DCCS_Handle)dccsContent;
}

libdccssdk_EXPORT DCCS_Handle dccsSDK_lib_initWithDCCSURL(char *ServiceKey, char *DCCSportocol, char *DCCShost, char *DCCSpath, int *Ret)
{
	int iReturn = DCCS_SUCCESS;
	dccsSDK_t *dccsContent = NULL;

	if (ServiceKey == NULL || DCCSportocol == NULL || DCCShost == NULL || DCCSpath == NULL)
	{
		iReturn = DCCS_ERR_PARAMETERS_ERROR;
		goto FUNC_EXIT;
	}

	if (strcmp(DCCSportocol, "http") != EQUAL && strcmp(DCCSportocol, "https") != EQUAL)
	{
		iReturn = DCCS_ERR_PARAMETERS_ERROR;
		goto FUNC_EXIT;
	}

	memset(g_DCCS_PORTOCOL, 0, sizeof(g_DCCS_PORTOCOL));
	memset(g_DCCS_HOST, 0, sizeof(g_DCCS_HOST));
	memset(g_DCCS_PATH, 0, sizeof(g_DCCS_PATH));
	strcpy(g_DCCS_PORTOCOL, DCCSportocol);
	strcpy(g_DCCS_HOST, DCCShost);
	strcpy(g_DCCS_PATH, DCCSpath);

	dccsContent = (dccsSDK_t*)malloc(sizeof(dccsSDK_t));
	memset(dccsContent, 0, sizeof(dccsSDK_t));
	
	dccsContent->ServiceKey = strdup(ServiceKey);
	dccsContent->RetryNum = 0;

FUNC_EXIT:
	if (Ret != NULL)
		*Ret = iReturn;
	if (iReturn != DCCS_SUCCESS)
		return NULL;
	else
		return (DCCS_Handle)dccsContent;
}

libdccssdk_EXPORT int dccsSDK_lib_cleanup(DCCS_Handle dccsHandle)
{
	dccsSDK_t *dccsContent = NULL;
	
	if (dccsHandle == NULL)
		return DCCS_ERR_LIB_NOT_INIT;

	dccsContent = (dccsSDK_t*)dccsHandle;
		
	if (dccsContent->ServiceKey != NULL)
		free(dccsContent->ServiceKey);
	if (dccsContent->TopicSubscribe != NULL)
		free(dccsContent->TopicSubscribe);
	if (dccsContent->TopicPublish != NULL)
		free(dccsContent->TopicPublish);
	if (dccsContent->SSLInfo != NULL)
		free(dccsContent->SSLInfo);
	free(dccsContent);
	
	dccsHandle = NULL;

	return DCCS_SUCCESS;
}

libdccssdk_EXPORT const char *dccsSDK_lib_getAllowPublishTopic(DCCS_Handle dccsHandle, int *Ret)
{
	int iReturn = DCCS_SUCCESS;
	dccsSDK_t *dccsContent = NULL;

	if (dccsHandle == NULL)
	{
		iReturn = DCCS_ERR_LIB_NOT_INIT ;
		goto FUNC_EXIT;
	}
	dccsContent = (dccsSDK_t*)dccsHandle;

	if (dccsContent->ServiceKey == NULL)
	{
		iReturn = DCCS_ERR_UNBIND_SERVICEKEY ;
		goto FUNC_EXIT;
	}

	iReturn = dccs_checkMQTTConnectInfo(dccsContent);
	if (iReturn != DCCS_SUCCESS)
		goto FUNC_EXIT;

FUNC_EXIT:
	if (iReturn != DCCS_SUCCESS)
	{
		if (Ret != NULL)
			*Ret = iReturn;
		return NULL;
	}
	else
	{
		if (Ret != NULL)
		{
			if (dccsContent->TopicPublish != NULL)
				*Ret = DCCS_GET_ALLOW_TOPIC_LIMITED;
			else
				*Ret = DCCS_GET_ALLOW_TOPIC_NO_LIMIT;
		}
		return dccsContent->TopicPublish;
	}
}

libdccssdk_EXPORT const char *dccsSDK_lib_getAllowSubscribeTopic(DCCS_Handle dccsHandle, int *Ret)
{
	int iReturn = DCCS_SUCCESS;
	dccsSDK_t *dccsContent = NULL;

	if (dccsHandle == NULL)
	{
		iReturn = DCCS_ERR_LIB_NOT_INIT ;
		goto FUNC_EXIT;
	}
	dccsContent = (dccsSDK_t*)dccsHandle;

	if (dccsContent->ServiceKey == NULL)
	{
		iReturn = DCCS_ERR_UNBIND_SERVICEKEY ;
		goto FUNC_EXIT;
	}

	iReturn = dccs_checkMQTTConnectInfo(dccsContent);
	if (iReturn != DCCS_SUCCESS)
		goto FUNC_EXIT;

FUNC_EXIT:
	if (iReturn != DCCS_SUCCESS)
	{
		if (Ret != NULL)
			*Ret = iReturn;
		return NULL;
	}
	else
	{
		if (Ret != NULL)
		{
			if (dccsContent->TopicSubscribe != NULL)
				*Ret = DCCS_GET_ALLOW_TOPIC_LIMITED;
			else
				*Ret = DCCS_GET_ALLOW_TOPIC_NO_LIMIT;
		}
		return dccsContent->TopicSubscribe;
	}
}

libdccssdk_EXPORT int dccsSDK_lib_publish(DCCS_Handle dccsHandle, char *Topic, int Payloadlen, const void *Payload, int Qos, int withSSL)
{
	int iReturn = DCCS_SUCCESS;
	dccsSDK_t *dccsContent = NULL;
	struct mosquitto *mosq = NULL;
	int iMosqRet = 0;
	connectContent_t *connectInfo = NULL; 
	char szRandomId[16];
	
	if (dccsHandle == NULL)
		return DCCS_ERR_LIB_NOT_INIT;
	if (Topic == NULL)
		return DCCS_ERR_PARAMETERS_ERROR;
	
	dccsContent = (dccsSDK_t*)dccsHandle;

	if (dccsContent->ServiceKey == NULL)
		return DCCS_ERR_UNBIND_SERVICEKEY;

	if (withSSL != TRUE && withSSL != FALSE)
		return DCCS_ERR_PARAMETERS_ERROR;
	dccsContent->withSSL = withSSL;

	iReturn = dccs_checkMQTTConnectInfo(dccsContent);
	if (iReturn != DCCS_SUCCESS)
		return iReturn;

	if (dccsContent->withSSL == TRUE)
	{
		if (dccsContent->SSLInfo == NULL)
			return DCCS_ERR_NOT_SUPPORT_SSL;
	}

	if (dccsContent->TopicPublish != NULL)
	{
		char *pszAllowTopic = NULL;
		char *pszSplit = NULL, *hTok = NULL;
		char *pszDot = NULL;

		pszAllowTopic = strdup(dccsContent->TopicPublish);

		pszSplit = dccs_strtok(pszAllowTopic, ",", &hTok);
		while(pszSplit != NULL)
		{
			pszDot = strstr(Topic, pszSplit);
			if (pszDot == Topic)
				break;
			pszSplit = dccs_strtok(NULL, ",", &hTok);
		}

		free(pszAllowTopic);
		if (pszDot == NULL)
			return DCCS_ERR_TOPIC_NOT_ALLOW;
	}

	//Use MQTT Client
	connectInfo = (connectContent_t*)malloc(sizeof(connectContent_t));
	memset(connectInfo, 0, sizeof(connectContent_t));

	connectInfo->dccsContent = dccsContent;
	connectInfo->Topic = Topic;
	connectInfo->Payload = Payload;
	connectInfo->Payloadlen = Payloadlen;
	connectInfo->Qos = Qos;

	connectInfo->bIsPub = TRUE;

	memset(szRandomId, 0, sizeof(szRandomId));
	strcpy(szRandomId, mosquitto_getRandomId());

	//PSK & PSK_Identity (Temporary -> Use Random Id)
	if (dccsContent->withSSL == TRUE)
	{
		strcpy(dccsContent->SSLInfo->PSK, szRandomId);
		strcpy(dccsContent->SSLInfo->PSK_Identity, szRandomId);
	}

	mosquitto_lib_init();
	mosq = mosquitto_new(szRandomId, 1, connectInfo);

	mosquitto_connect_callback_set(mosq, mosquitto_connect_callback);
	mosquitto_publish_callback_set(mosq, mosquitto_publish_callback);
	if (dccsContent->withSSL == TRUE)
	{
		if (mosquitto_tls_psk_set(mosq, szRandomId, szRandomId, NULL) != MOSQ_ERR_SUCCESS)
		{
			free(connectInfo);
			return DCCS_ERR_MQTT_CLIENT_FAIL;
		}
		mosquitto_username_pw_set(mosq, dccsContent->SSLInfo->Username, dccsContent->SSLInfo->Password);
		iMosqRet = mosquitto_connect(mosq, dccsContent->BrokeHost, dccsContent->SSLInfo->Port, 30);
	}
	else
	{
		mosquitto_username_pw_set(mosq, dccsContent->Username, dccsContent->Password);
		iMosqRet = mosquitto_connect(mosq, dccsContent->BrokeHost, dccsContent->Port, 30);
	}

	mosquitto_loop_forever(mosq, -1, 1);

	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();

	//free connectInfo
	free(connectInfo);

	return iReturn;
}

libdccssdk_EXPORT int dccsSDK_lib_subscribe(DCCS_Handle dccsHandle, char *Topic, int Qos, int withSSL, recvMsgCB CB_Func)
{
	int iReturn = DCCS_SUCCESS;
	dccsSDK_t *dccsContent = NULL;
	struct mosquitto *mosq = NULL;
	int iMosqRet = 0;
	connectContent_t *connectInfo = NULL;
	char szRandomId[16];
	
	if (dccsHandle == NULL)
		return DCCS_ERR_LIB_NOT_INIT;
	if (Topic == NULL || CB_Func == NULL)
		return DCCS_ERR_PARAMETERS_ERROR;
	
	dccsContent = (dccsSDK_t*)dccsHandle;

	if (dccsContent->ServiceKey == NULL)
		return DCCS_ERR_UNBIND_SERVICEKEY;

	if (withSSL != TRUE && withSSL != FALSE)
		return DCCS_ERR_PARAMETERS_ERROR;
	dccsContent->withSSL = withSSL;

	iReturn = dccs_checkMQTTConnectInfo(dccsContent);
	if (iReturn != DCCS_SUCCESS)
		return iReturn;

	if (dccsContent->withSSL == TRUE)
	{
		if (dccsContent->SSLInfo == NULL)
			return DCCS_ERR_NOT_SUPPORT_SSL;
	}

	if (dccsContent->TopicSubscribe != NULL)
	{
		char *pszAllowTopic = NULL;
		char *pszSplit = NULL, *hTok = NULL;
		char *pszDot = NULL;

		pszAllowTopic = strdup(dccsContent->TopicSubscribe);

		pszSplit = dccs_strtok(pszAllowTopic, ",", &hTok);
		while(pszSplit != NULL)
		{
			pszDot = strstr(Topic, pszSplit);
			if (pszDot == Topic)
				break;
			pszSplit = dccs_strtok(NULL, ",", &hTok);
		}

		free(pszAllowTopic);
		if (pszDot == NULL)
			return DCCS_ERR_TOPIC_NOT_ALLOW;
	}

	memset(szRandomId, 0, sizeof(szRandomId));
	strcpy(szRandomId, mosquitto_getRandomId());

	//PSK & PSK_Identity (Temporary -> Use Random Id)
	if (dccsContent->withSSL == TRUE)
	{
		strcpy(dccsContent->SSLInfo->PSK, szRandomId);
		strcpy(dccsContent->SSLInfo->PSK_Identity, szRandomId);
	}
	
	//Use MQTT Client
	mosquitto_lib_init();

	connectInfo = (connectContent_t*)malloc(sizeof(connectContent_t));
	memset(connectInfo, 0, sizeof(connectContent_t));

	connectInfo->dccsContent = dccsContent;
	connectInfo->Topic = Topic;
	connectInfo->CB_Func = CB_Func;

	connectInfo->bIsPub = FALSE;

	mosq = mosquitto_new(szRandomId, 1, connectInfo);

	mosquitto_connect_callback_set(mosq, mosquitto_connect_callback);
	mosquitto_subscribe_callback_set(mosq, mosquitto_subscribe_callback);
	mosquitto_message_callback_set(mosq, mosquitto_message_callback);

	if (dccsContent->withSSL == TRUE)
	{
		if (mosquitto_tls_psk_set(mosq, szRandomId, szRandomId, NULL) != MOSQ_ERR_SUCCESS)
		{
			free(connectInfo);
			return DCCS_ERR_MQTT_CLIENT_FAIL;
		}
		mosquitto_username_pw_set(mosq, dccsContent->SSLInfo->Username, dccsContent->SSLInfo->Password);
		iMosqRet = mosquitto_connect(mosq, dccsContent->BrokeHost, dccsContent->SSLInfo->Port, 30);
	}
	else
	{
		mosquitto_username_pw_set(mosq, dccsContent->Username, dccsContent->Password);
		iMosqRet = mosquitto_connect(mosq, dccsContent->BrokeHost, dccsContent->Port, 30);
	}

	mosquitto_loop_forever(mosq, -1, 1);

FUNC_EXIT:
	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
	return iReturn;
}