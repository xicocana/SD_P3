package example.ws.handler;

import java.io.PrintStream;
import java.io.StringWriter;
import java.security.Key;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import javax.xml.namespace.QName;
import javax.xml.soap.Name;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.MessageContext.Scope;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;
import java.security.*;
import org.w3c.dom.Node;
import java.io.*;
import pt.ulisboa.tecnico.sdis.kerby.Auth;
import pt.ulisboa.tecnico.sdis.kerby.CipherClerk;
import pt.ulisboa.tecnico.sdis.kerby.CipheredView;
import pt.ulisboa.tecnico.sdis.kerby.SecurityHelper;
import pt.ulisboa.tecnico.sdis.kerby.Ticket;

public class MACHandler implements SOAPHandler<SOAPMessageContext> {
	/** Message authentication code algorithm. */
	private static final String MAC_ALGO = "HmacSHA256";
	public static final String CONTEXT_PROPERTY3 = "my.property3";
    public static final String CONTEXT_PROPERTY4 = "my.property4";
    /**
     * Gets the names of the header blocks that can be processed by this Handler instance.
     * If null, processes all.
     */
    public Set getHeaders() {
        return null;
    }

    /**
     * The handleMessage method is invoked for normal processing of inbound and
     * outbound messages.
     */
     public boolean handleMessage(SOAPMessageContext smc) {
    	return MACProcessing(smc, System.out);  
    }

    /** The handleFault method is invoked for fault message processing. */
    public boolean handleFault(SOAPMessageContext smc) {
    	MACProcessing(smc, System.out);  
        return true;
    }

    /**
     * Called at the conclusion of a message exchange pattern just prior to the
     * JAX-WS runtime dispatching a message, fault or exception.
     */
    public void close(MessageContext messageContext) {
    	// nothing to clean up
    }
    
    private boolean MACProcessing(SOAPMessageContext smc, PrintStream out){
   	 Boolean isRequest = (Boolean) smc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
   	 int ataque = 0;
   	 	if(isRequest){
   	 		//CLIENT SIDE
	   	 	try{
	       	 	Key serverKey;
	            CipheredView cipheredTicket = null;
	            Auth authServer = null;
	            CipheredView cipheredAuth = null;
	            Ticket ticket = null;
	            //get SOAP envelope
	            SOAPMessage msg = smc.getMessage();
	            SOAPPart sp = msg.getSOAPPart();
	            SOAPEnvelope se = sp.getEnvelope();
	            SOAPHeader header = se.getHeader();
	            SOAPBody body = se.getBody();
	            
	            if(header == null){
	                header = se.addHeader(); 
	            }
	            CipherClerk clerk = new CipherClerk(); 
	            CipherClerk clerk2 = new CipherClerk(); 
	
	            Node node = header.getElementsByTagName("ticket").item(0);
	            if(node != null){
	                cipheredTicket = clerk.cipherFromXMLNode(node);
	            }
	            
	            Node node1 =  header.getElementsByTagName("auth").item(0);	           
	            if(node1 != null){
	                cipheredAuth = clerk2.cipherFromXMLNode(node1);
	            }
	             
	            serverKey = SecurityHelper.generateKeyFromPassword("OLg3xULZq");
	
	            ticket = new Ticket(cipheredTicket, serverKey); //TICKET
	            Key kcs = ticket.getKeyXY();	//KEY 
	            authServer = new Auth(cipheredAuth, kcs); //AUTH
	            
	            String bodyString = bodyConverter(body);
	            byte[] bodyByte = bodyString.getBytes();
	            byte[] mac = makeMAC(bodyByte,kcs);
	            String mac_string = DatatypeConverter.printBase64Binary(mac);
	            
				Name name = se.createName("MAC", "t", "http://ticket");
				SOAPHeaderElement element = header.addHeaderElement(name);

				// add header element value
				element.addTextNode(mac_string);
	           
                msg.saveChanges();

                
                
	   	 	}catch(Exception e){
    			System.err.println("Caught exception on MACHandler OUTBOUND : " + e);
            }

            return true;
	   	 	
   	 	}else {
   	 		//SERVER SIDE
	   	 	try{
	       	 	Key serverKey;
	            CipheredView cipheredTicket = null;
	            Auth authServer = null;
	            CipheredView cipheredAuth = null;
	            Ticket ticket = null;
	            //get SOAP envelope
	            SOAPMessage msg = smc.getMessage();
	            SOAPPart sp = msg.getSOAPPart();
	            SOAPEnvelope se = sp.getEnvelope();
	            SOAPHeader header = se.getHeader();
	            SOAPBody body = se.getBody();
	            
	            if(header == null){
	                header = se.addHeader(); 
	            }
	            
	            CipherClerk clerk2 = new CipherClerk(); 
	            
	            Node node1 =  header.getElementsByTagName("ticket").item(0);
	            if(node1 != null){
	                cipheredTicket = clerk2.cipherFromXMLNode(node1);
	            }
	            
	            // get first header element
				Name name = se.createName("MAC", "t", "http://ticket");
				Iterator<?> it = header.getChildElements(name);
				// check header element
				if (!it.hasNext()) {
					System.out.println("Header element not found.");
				}
				SOAPElement element = (SOAPElement) it.next();

				// get header element value
				String string_mac = element.getValue();
				
				// print received header
				serverKey = SecurityHelper.generateKeyFromPassword("OLg3xULZq");
				
				ticket = new Ticket(cipheredTicket, serverKey);

                Key kcs = ticket.getKeyXY();
	           
	            byte[] good_mac = DatatypeConverter.parseBase64Binary(string_mac);
	            
	            String bodyString = bodyConverter(body);
	            byte[] bodyByte = bodyString.getBytes();
	           
	            if(verifyMAC(good_mac, bodyByte, kcs)){
	            	System.out.println("MESSAGE AUTHENTICATED");
	            }else {
	            	System.out.println("ATTACK DETECTED");
	            	ataque = 1;
	            	throw new RuntimeException();
	            }
	        	
	            
   	 		}catch(Exception e){
            	System.err.println("Caught exception on MACHandler INBOUND : " + e);
       	 	}

       	 	if(ataque == 1){
       	 		return false;
       	 	}
       	 	return true;
   	 	}
    }
    
    /** Makes a message authentication code. */
	private static byte[] makeMAC(byte[] bytes, Key key) throws Exception {

		Mac cipher = Mac.getInstance(MAC_ALGO);
		cipher.init(key);
		byte[] cipherDigest = cipher.doFinal(bytes);

		return cipherDigest;
	}

	/**
	 * Calculates new digest from text and compare it to the to deciphered
	 * digest.
	 */
	private static boolean verifyMAC(byte[] cipherDigest, byte[] bytes, Key key) throws Exception {

		Mac cipher = Mac.getInstance(MAC_ALGO);
		cipher.init(key);
		byte[] cipheredBytes = cipher.doFinal(bytes);
		return Arrays.equals(cipherDigest, cipheredBytes);
	}
	
	private String bodyConverter(Node node) throws Exception {
		Transformer transformer = TransformerFactory.newInstance().newTransformer();
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");        
		StringWriter sw = new StringWriter();
		StreamResult result = new StreamResult(sw);
		DOMSource source = new DOMSource(node);
		transformer.transform(source, result);
		String xmlString = sw.toString();
		return xmlString;
		
	}
}