package dccsSDK;

import java.io.IOException;
import java.sql.Timestamp;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttCallback;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.persist.MqttDefaultFilePersistence;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class dccs_SDK  implements MqttCallback{
	
	private static String responseBody;
	public static String key;
	public static String host = null;
	public static  JsonObject object;
	
    public dccs_SDK(String dccsKey) throws ClientProtocolException, IOException, MqttException {
    		key = dccsKey;
    		HttpGet httpget = new HttpGet("https://api-dccs.wise-paas.com/v1/serviceCredentials/"+dccsKey);  
    		CloseableHttpClient httpclient = HttpClients.createDefault();
    			ResponseHandler<String> responseHandler = new ResponseHandler<String>() {
            @Override
            public String handleResponse(final HttpResponse response) throws ClientProtocolException, IOException {
                int status = response.getStatusLine().getStatusCode();
                if (status >= 200 && status < 300) {
                    HttpEntity entity = response.getEntity();
                    return entity != null ? EntityUtils.toString(entity) : null;
                } 
                
                else {
                	 throw new ClientProtocolException("Http Exception Code: " + status);
                }
            }  
        };
     responseBody = httpclient.execute(httpget, responseHandler);
     object = new JsonParser().parse(responseBody).getAsJsonObject();
     paho(object);
    }
    
    public dccs_SDK(String dccsUrl,String dccsKey) throws ClientProtocolException, IOException, MqttException {
    	key = dccsKey;
    	host = dccsUrl;
    		HttpGet httpget = new HttpGet(dccsUrl+dccsKey);  
    		CloseableHttpClient httpclient = HttpClients.createDefault();
    			ResponseHandler<String> responseHandler = new ResponseHandler<String>() {
            @Override
            public String handleResponse(final HttpResponse response) throws ClientProtocolException, IOException {
                int status = response.getStatusLine().getStatusCode();
                if (status >= 200 && status < 300) {
                    HttpEntity entity = response.getEntity();
                    return entity != null ? EntityUtils.toString(entity) : null;
                } else {
                    throw new ClientProtocolException("Http Exception Code: " + status);
                }
            }  
        };
     responseBody = httpclient.execute(httpget, responseHandler);
     object = new JsonParser().parse(responseBody).getAsJsonObject();
     paho(object);
    }
	
	private MqttClient 	client;
	private String 	brokerUrl;
	private boolean 	quietMode;
	private MqttConnectOptions conOpt;
	private boolean 	clean;
	private String password;
	private String userName;

    public void paho(JsonObject dccsContent) throws MqttException, ClientProtocolException, IOException {
    	String protocol = "tcp://";
    	String clientId = "java_SDK"+Math.random()*10;
    	String broker = object.get("serviceHost").getAsString();
    int 	port = object.get("credential").getAsJsonObject().get("protocols").getAsJsonObject().get("mqtt").getAsJsonObject().get("port").getAsInt();
    this.userName = object.get("credential").getAsJsonObject().get("protocols").getAsJsonObject().get("mqtt").getAsJsonObject().get("username").getAsString();
    this.password = object.get("credential").getAsJsonObject().get("protocols").getAsJsonObject().get("mqtt").getAsJsonObject().get("password").getAsString();
    this.brokerUrl = protocol + broker + ":" + port;
    	this.clean 	   = true;
    this.quietMode =  true;
    	String tmpDir = System.getProperty("java.io.tmpdir");
    	MqttDefaultFilePersistence dataStore = new MqttDefaultFilePersistence(tmpDir);

    	try {
	    	conOpt = new MqttConnectOptions();
	    	conOpt.setCleanSession(clean);
	    	if(password != null ) {
	    	  conOpt.setPassword(this.password.toCharArray());
	    	}
	    	if(userName != null) {
	    	  conOpt.setUserName(this.userName);
	    	}
			client = new MqttClient(this.brokerUrl,clientId, dataStore);
	    		client.setCallback(this);
		} catch (MqttException e) {
			if (e.getReasonCode()==5) {
				for(int i=1;i<2;i++) {
				conOpt = new MqttConnectOptions();
			    	conOpt.setCleanSession(clean);
			    	if(password != null ) {
			    	  conOpt.setPassword(this.password.toCharArray());
			    	}
			    	if(userName != null) {
			    	  conOpt.setUserName(this.userName);
			    	}
				client = new MqttClient(this.brokerUrl,clientId, dataStore);	
			    	client.setCallback(this);
				}
				System.exit(1);
			}
			else if (e.getReasonCode()==32002) {
				for(int i=1;i<2;i++) {
				conOpt = new MqttConnectOptions();
			    	conOpt.setCleanSession(clean);
			    	if(password != null ) {
			    	  conOpt.setPassword(this.password.toCharArray());
			    	}
			    	if(userName != null) {
			    	  conOpt.setUserName(this.userName);
			    	}
				client = new MqttClient(this.brokerUrl,clientId, dataStore);	
			    	client.setCallback(this);
				}
				System.exit(1);
			}
			else if (e.getReasonCode()==32109) {
				for(int i=1;i<2;i++) {
				conOpt = new MqttConnectOptions();
			    	conOpt.setCleanSession(clean);
			    	if(password != null ) {
			    	  conOpt.setPassword(this.password.toCharArray());
			    	}
			    	if(userName != null) {
			    	  conOpt.setUserName(this.userName);
			    	}
				client = new MqttClient(this.brokerUrl,clientId, dataStore);	
			    	client.setCallback(this);
				}
				System.exit(1);
			}
			else if (e.getReasonCode()==4) {
				for(int i=1;i<2;i++) {
					if (host==null) {
						new dccs_SDK(key);	
					}else {
						new dccs_SDK(host,key);
					}	
				}
			}
			else {
				System.out.println("MQTT Exception Code :"+e.getReasonCode());
				System.out.println("Please check MQTT password and username");
				System.exit(1);
			}
		}
    }

	public void publish(String topicName, int qos, String Spayload) throws MqttException {
    byte[] payload;
    	if (qos < 0 || qos > 2) {
			System.out.println("Invalid QoS: "+qos);
			return ;
		}
    	payload = Spayload.getBytes();
    log("Connecting to "+brokerUrl + " with client ID "+client.getClientId());
    	client.connect(conOpt);
    	log("Connected");
    	log("Publishing at: "+ new Timestamp(System.currentTimeMillis()).toString() + " to topic \""+topicName+"\" qos "+qos);
    	MqttMessage message = new MqttMessage(payload);
    	message.setQos(qos);
    	client.publish(topicName, message);  	
    	client.disconnect();
    log("Disconnected");
    }
    
    public void subscribe(String topicName, int qos) throws MqttException {
    	if (qos < 0 || qos > 2) {
			System.out.println("Invalid QoS: "+qos);
			return ;
		}
    client.connect(conOpt);
    
    client.subscribe(topicName, qos);
		try {
			System.in.read();
		} catch (IOException e) {
		}
	    client.disconnect();
    }
    
    private void log(String message) {
    		if (!quietMode) {
    			System.out.println(message);
    		}
    }

	private MqttCallback MQTTListener = null;
	
	public void setMQTTListener(MqttCallback l) {
		MQTTListener = l;
	}
    
	public void connectionLost(Throwable cause) {
		try {
			paho(object);
		} catch (MqttException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("Connection to " + brokerUrl + " lost!" + cause);
		System.exit(1);
		
	}

	public void deliveryComplete(IMqttDeliveryToken token) {
	}
	
	public void messageArrived(String topic, MqttMessage message) throws MqttException {
		try {
			MQTTListener.messageArrived(topic, message);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		log("Time:\t" + new Timestamp(System.currentTimeMillis()).toString() +"  Topic:\t" + topic +"  Message:\t" + new String(message.getPayload()) + "  QoS:\t" + message.getQos());
	}
	
  
}



