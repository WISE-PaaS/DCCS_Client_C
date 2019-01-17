# 前置作業 #
=================================================================================================
- DynamicCredentialConfigurationService_SDK需相依3個library

	- Apache httpclient
		- https://hc.apache.org/httpcomponents-client-ga/
	- Eclipse Paho Java Client
		- https://www.eclipse.org/paho/clients/java/
	- Google gson (JSON parser)
		- http://www.java2s.com/Code/Jar/g/Downloadgson222jar.htm


# 使用說明#
=================================================================================================

	1. 建立新的dccs_SDK物件，並取得帳號密碼，支援多型
	dccs_SDK Client = dccs_SDK(String dccsKey)
	dccs_SDK Client = dccs_SDK(String dccsUrl,String dccsKey)
		
	2. dccs_SDK物件使用dccs_SDK中的publish方法
	Client.publish(String pubTopic,int qos,String pubMessage)
		
	3. dccs_SDK物件使用dccs_SDK中的subscribe方法
	Client.subscribe(String subTopic,int qos)
	
	4. 針對收到監聽訊息做出反應，需要透過Callback搭配多執行緒
	 static dccs_SDK Listener = null;
	 run(){
	 
	 Listener= new dccs_SDK(String dccsKey);
	 Listener.setMQTTListener(this);
	 Client.subscribe(String subTopic,int qos)
	 
	 }
	
	
# 範例#
=================================================================================================
- dccs_SDK Client = new dccs_SDK("8e4297f56de1ec333557d5778ac496b5");
	-給定dccs_SDK初始值，並建立物件Client裝載MQTT連線的資訊
	
- Client.publish("/Topic",0,"pubMsg");
	-Client物件使用publish方法發送訊息(所有連線設定,qos的設定0-2,訂閱的主題)
	
- Client.subscribe("/Topic",0,);
	-Client物件使用subscribe方法監聽訊息(訂閱的主題,qos的設定0-2)
