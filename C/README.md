# 前置作業 #
=================================================================================================
- DynamicCredentialConfigurationService_SDK需相依3個library

	- OpenSSL (HTTPS Library)
		- https://www.openssl.org/
	- Mosquitto (MQTT Client)
		- https://mosquitto.org/
	- Jansson (JSON parser)
		- http://www.digip.org/jansson/

# 使用說明#
=================================================================================================

	1. Build OpenSSL (..\DynamicCredentialConfigurationService_SDK\C\AdditionalDependenciesLibrary\libopenssl)
	
		tar -zxvf openssl-1.0.1c.tar.gz
		./config -d shared
		make
		產生 libssl.so
		
	2. Build Mosquitto (..\DynamicCredentialConfigurationService_SDK\C\AdditionalDependenciesLibrary\libmosquitto)
		make
		產生 libmosquitto.so

	3. Build Jansson  (..\DynamicCredentialConfigurationService_SDK\C\AdditionalDependenciesLibrary\libjansson)
		make
		產生 libjansson.so
		
	4. Build DCCS SDK  (..\DynamicCredentialConfigurationService_SDK\C\SDK)
		make
		產生 libdccssdk.so
		
	5. 使用Sample   (..\DynamicCredentialConfigurationService_SDK\C\Sample)
	
	
# C Code API介面#
=================================================================================================
- libdccssdk_EXPORT DCCS_Handle dccsSDK_lib_init(char *ServiceKey);
	- Initial DCCS_SDK Library. Must be called before any other mosquitto functions.
	- @param ServiceKey (in) Service Key. Use UUID format.
	- @returns NULL: Error, DCCS_Handle: Success(This DCCS_SDK Handle)

- libdccssdk_EXPORT int dccsSDK_lib_cleanup(DCCS_Handle dccsContent);
	- Call to free resources associated with the library.
	- @param dccsContent (in) DCCS_SDK Handle.
	- @returns DCCS_SUCCESS: Success, else: Fail. Reference Error Code

- libdccssdk_EXPORT const char *dccsSDK_lib_getAllowPublishTopic(DCCS_Handle dccsHandle, int *Ret);
	- Call to get allow publish topic. Use ',' separate multiple topic. Example: /AAA/BBB/CCC,/XXX/YYY/ZZZ,/III/JJJ
	- @param dccsContent (in) DCCS_SDK Handle.
	- @param Ret (in/out) Input integer pointer. Will return get status. DCCS_GET_ALLOW_TOPIC_NO_LIMIT: Topic no limit, DCCS_GET_ALLOW_TOPIC_LIMITED: Topic limited, Other: Error Code
	- @returns NULL: Error, (const char*)Topic: Success

- libdccssdk_EXPORT const char *dccsSDK_lib_getAllowSubscribeTopic(DCCS_Handle dccsHandle, int *Ret);
	- Call to get allow subscribe topic. Use ',' separate multiple topic. Example: /AAA/BBB/CCC,/XXX/YYY/ZZZ,/III/JJJ
	- @param dccsContent (in) DCCS_SDK Handle.
	- @param Ret (in/out) Input integer pointer. Will return get status. DCCS_GET_ALLOW_TOPIC_NO_LIMIT: Topic no limit, DCCS_GET_ALLOW_TOPIC_LIMITED: Topic limited, Other: Error Code
	- @returns NULL: Error, (const char*)Topic: Success

- libdccssdk_EXPORT int dccsSDK_lib_publish(DCCS_Handle dccsHandle, char *Topic, int Payloadlen, const void *Payload, int Qos, int withSSL);
	- Publish a message on a given topic. Auto Get DCCS Credential.
	- @param dccsContent (in) DCCS_SDK Handle.
	- @param TOPIC (in) String of the topic to publish to.
	- @param Payloadlen (in) The size of the payload (bytes).
	- @param Payload (in) Pointer to the data to send.
	- @param Qos (in) Integer value 0, 1 or 2 indicating the Quality of Service to be used for the message.
	- @param withSSL (in) Boolean vlaue True(1) or False(0). Configure the parm to True for pre-shared-key based TLS support.
	- @returns DCCS_SUCCESS: Success, else: Fail. Reference Error Code

- typedef void (*recvMsgCB)(int Msglen, const void *Msg);
	- Callback Function : Recv Subscribe Message
	- @param Msglen (out) The size of the recv message (bytes).
	- @param Msg (out) Pointer to the data to recv.

- libdccssdk_EXPORT int dccsSDK_lib_subscribe(DCCS_Handle dccsHandle, char *Topic, int Qos, int withSSL, recvMsgCB CB_Func);
	- Subscribe to a topic. Auto Get DCCS Credential.
	- @param dccsContent (in) DCCS_SDK Handle.
	- @param TOPIC (in) String of the topic to publish to.
	- @param Qos (in) Integer value 0, 1 or 2 indicating the Quality of Service to be used for the message.
	- @param withSSL (in) Boolean vlaue True(1) or False(0). Configure the parm to True for pre-shared-key based TLS support.
	- @param CB_Func (in) Recv message callback function.
	- @returns DCCS_SUCCESS: Success, else: Fail. Reference Error Code