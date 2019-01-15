#ifdef WIN32
#define libdccssdk_EXPORT __declspec(dllexport)
#else
#define libdccssdk_EXPORT
#endif

#define DCCS_Handle void*

#define DCCS_SUCCESS 0

#define DCCS_ERR_CREDENTIAL_NOT_FOUND 404
#define DCCS_ERR_CREDENTIAL_GONE 410
#define DCCS_ERR_CREDENTIAL -1
#define DCCS_ERR_LIB_NOT_INIT -2
#define DCCS_ERR_UNBIND_SERVICEKEY -3
#define DCCS_ERR_PARAMETERS_ERROR -4
#define DCCS_ERR_INTERNET_ERROR -5
#define DCCS_ERR_INTERNAL_ERROR -6
#define DCCS_ERR_TOPIC_NOT_ALLOW -7
#define DCCS_ERR_MQTT_CLIENT_FAIL -8
#define DCCS_ERR_NOT_SUPPORT_SSL -9
#define DCCS_ERR_UNKNOWN -10

#define DCCS_GET_ALLOW_TOPIC_NO_LIMIT 0
#define DCCS_GET_ALLOW_TOPIC_LIMITED 1

//Initial DCCS_SDK Library. Must be called before any other dccsSDK functions. Default DCCS Service URL : https://api-dccs-develop.iii-cflab.com/v1/serviceCredentials/
//@param ServiceKey (in) Service Key. Use UUID format.
//@returns NULL: Error, DCCS_Handle: Success(This DCCS_SDK Handle)
libdccssdk_EXPORT DCCS_Handle dccsSDK_lib_init(char *ServiceKey);

//Initial DCCS_SDK Library. Must be called before any other dccsSDK functions. Setting DCCS Service URL.
//@param ServiceKey (in) Service Key. Use UUID format.
//@param DCCSportocol (in) DCCS Serice Portocol. "https" or "http"
//@param DCCShost (in) DCCS Serice Host Name. Example: api-dccs-develop.iii-cflab.com
//@param DCCSpath (in) DCCS Serice Path. Example: /v1/serviceCredentials/
//@param Ret (in/out) Input integer pointer. Will return error code.
//@returns NULL: Error, DCCS_Handle: Success(This DCCS_SDK Handle)
libdccssdk_EXPORT DCCS_Handle dccsSDK_lib_initWithDCCSURL(char *ServiceKey, char *DCCSportocol, char *DCCShost, char *DCCSpath, int *Ret);

//Call to free resources associated with the library.
//@param dccsContent (in) DCCS_SDK Handle.
//@returns DCCS_SUCCESS: Success, else: Fail. Reference Error Code
libdccssdk_EXPORT int dccsSDK_lib_cleanup(DCCS_Handle dccsContent);

//Call to get allow publish topic. Use ',' separate multiple topic. Example: /AAA/BBB/CCC,/XXX/YYY/ZZZ,/III/JJJ
//@param dccsContent (in) DCCS_SDK Handle.
//@param Ret (in/out) Input integer pointer. Will return get status. DCCS_GET_ALLOW_TOPIC_NO_LIMIT: Topic no limit, DCCS_GET_ALLOW_TOPIC_LIMITED: Topic limited, Other: Error Code
//@returns NULL: Error, (const char*)Topic: Success
libdccssdk_EXPORT const char *dccsSDK_lib_getAllowPublishTopic(DCCS_Handle dccsHandle, int *Ret);

//Call to get allow subscribe topic. Use ',' separate multiple topic. Example: /AAA/BBB/CCC,/XXX/YYY/ZZZ,/III/JJJ
//@param dccsContent (in) DCCS_SDK Handle.
//@param Ret (in/out) Input integer pointer. Will return get status. DCCS_GET_ALLOW_TOPIC_NO_LIMIT: Topic no limit, DCCS_GET_ALLOW_TOPIC_LIMITED: Topic limited, Other: Error Code
//@returns NULL: Error, (const char*)Topic: Success
libdccssdk_EXPORT const char *dccsSDK_lib_getAllowSubscribeTopic(DCCS_Handle dccsHandle, int *Ret);

//Publish a message on a given topic. Auto Get DCCS Credential.
//@param dccsContent (in) DCCS_SDK Handle.
//@param TOPIC (in) String of the topic to publish to.
//@param Payloadlen (in) The size of the payload (bytes).
//@param Payload (in) Pointer to the data to send.
//@param Qos (in) Integer value 0, 1 or 2 indicating the Quality of Service to be used for the message.
//@param withSSL (in) Boolean vlaue True(1) or False(0). Configure the parm to True for pre-shared-key based TLS support.
//@returns DCCS_SUCCESS: Success, else: Fail. Reference Error Code
libdccssdk_EXPORT int dccsSDK_lib_publish(DCCS_Handle dccsHandle, char *Topic, int Payloadlen, const void *Payload, int Qos, int withSSL);

//Callback Function : Recv Subscribe Message
//@param Msglen (out) The size of the recv message (bytes).
//@param Msg (out) Pointer to the data to recv.
typedef void (*recvMsgCB)(int Msglen, const void *Msg);

//Subscribe to a topic. Auto Get DCCS Credential.
//@param dccsContent (in) DCCS_SDK Handle.
//@param TOPIC (in) String of the topic to publish to.
//@param Qos (in) Integer value 0, 1 or 2 indicating the Quality of Service to be used for the message.
//@param withSSL (in) Boolean vlaue True(1) or False(0). Configure the parm to True for pre-shared-key based TLS support.
//@param CB_Func (in) Recv message callback function.
//@returns DCCS_SUCCESS: Success, else: Fail. Reference Error Code
libdccssdk_EXPORT int dccsSDK_lib_subscribe(DCCS_Handle dccsHandle, char *Topic, int Qos, int withSSL, recvMsgCB CB_Func);