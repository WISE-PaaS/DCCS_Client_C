package dccsSDK;


import java.io.IOException;
import org.apache.http.client.ClientProtocolException;
import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttCallback;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;



public class Sample extends Thread implements MqttCallback {
	//Setting Default

	public static String dccsUrl = "https://api-dccs.wise-paas.com/v1/serviceCredentials/";
	public static String dccsKey = "8e4297f56de1ec333557d5778ac496b5";
	public static dccs_SDK Listener = null;
	public void run() { 		
		
		try {	
			Listener= new dccs_SDK(dccsKey);
			// polymorphism
			// dccs_SDK Client = new dccs_SDK(dccsUrl,dccsKey);
			Listener.setMQTTListener(this);
			Listener.subscribe("/test/III",0);	
			
		}
		catch (MqttException e) {
			//e.printStackTrace();
		} catch (ClientProtocolException e) {
			//e.printStackTrace();
		} catch (IOException e) {
			//e.printStackTrace();
		}	
		
 } 

public static void main(String[] args)  throws ClientProtocolException, IOException, MqttException, InterruptedException {
		new Sample().start();   //Start subscribe	
		Thread.sleep(1000*5);  //break 2 Second
		dccs_SDK Client = new dccs_SDK(dccsKey); 		
		Client.publish("/test/III",0,"hi");
		Thread.sleep(1000*5);
		Client.publish("/test/III",0,"你好");
		Thread.sleep(1000*5);
		Client.publish("/test/III",0,"bonjour");
		Thread.sleep(1000*5);
		Client.publish("/test/III",0,"賀");
		//Thread.sleep(1000*5);  //break 2 Second
	  }

@Override
public void connectionLost(Throwable arg0) {
	// TODO Auto-generated method stub
	
}

@Override
public void deliveryComplete(IMqttDeliveryToken arg0) {
	// TODO Auto-generated method stub
	
}

@Override
public void messageArrived(String topic, MqttMessage Msg) throws Exception {
	// TODO Auto-generated method stub
	String arriveMsg = new String(Msg.getPayload());
	if(arriveMsg.equals("hi")) {
		System.out.println("英文");
		
	}else if (arriveMsg.equals("你好")) {
		System.out.println("中文");
	}
	else if (arriveMsg.equals("bonjour")){
		System.out.println("法文");
	}else {
		System.out.println("不知道");
	}
}

	}

