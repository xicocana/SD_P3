package example.ws.handler;
import org.w3c.dom.Node;
import java.util.Set;
import javax.xml.namespace.QName;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.MessageContext.Scope;
import javax.xml.soap.*;
import javax.xml.ws.handler.soap.*;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Properties;
import java.io.*;
import pt.ulisboa.tecnico.sdis.kerby.*;
import pt.ulisboa.tecnico.sdis.kerby.Auth;
import pt.ulisboa.tecnico.sdis.kerby.CipheredView;
import pt.ulisboa.tecnico.sdis.kerby.SecurityHelper;
import pt.ulisboa.tecnico.sdis.kerby.SessionKey;
import pt.ulisboa.tecnico.sdis.kerby.SessionKeyAndTicketView;
import pt.ulisboa.tecnico.sdis.kerby.Ticket;
import pt.ulisboa.tecnico.sdis.kerby.cli.KerbyClient;
import pt.ulisboa.tecnico.sdis.kerby.cli.*;
import java.security.*;
import java.lang.*;

public class BinasAuthorizationHandler implements SOAPHandler<SOAPMessageContext> {
	public static final String CONTEXT_PROPERTY = "my.property";
	final int VALID_DURATION = 30;
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
    	return AuthorizationProcessing(smc, System.out);
    }

    /** The handleFault method is invoked for fault message processing. */
    public boolean handleFault(SOAPMessageContext smc) {
    	return AuthorizationProcessing(smc, System.out);
    }

    /**
     * Called at the conclusion of a message exchange pattern just prior to the
     * JAX-WS runtime dispatching a message, fault or exception.
     */
    public void close(MessageContext messageContext) {

    }
    private boolean AuthorizationProcessing(SOAPMessageContext smc, PrintStream out){
    	 Boolean isRequest = (Boolean) smc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
    	 int flag = 0;
         if(!isRequest){
             try{
            	 Key serverKey;
                 CipheredView cipheredTicket = null;
                 Auth authServer = null;
                 CipheredView cipheredAuth = null;
                 Ticket ticket = null;
                 
                 // get SOAP envelope
                 SOAPMessage msg = smc.getMessage();
                 SOAPPart sp = msg.getSOAPPart();
                 SOAPEnvelope se = sp.getEnvelope();
                 SOAPHeader header = se.getHeader();
                 
                 String email_auth;
                 String email_ticket;
                 
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
                 
                 //VERIFICAÇAO DO EMAIL
                 
                 email_auth = authServer.getX(); //Email que vem no pedido
                 email_ticket = ticket.getX(); //Email com que foi feito o pedido
                 
                 if(email_auth.equals(email_ticket)) {
                	 System.out.println("ACCESS GRANTED");
                 }else{
                	 System.out.println("ACCESS DENIED");
                     flag = 1;
                	 throw new RuntimeException();
                 }
                 
                 //VERIFICAÇAO DO TEMPO
                 ticket.validate();
               
             }catch(Exception e){
                flag = 1;
                 System.err.println("Caught exception on BinasAuthorizationHandler INBOUND : " + e);
             }
         }
         if(flag == 1 ){
            return false;
         }else{
            return true;
         }
    	}
    }

