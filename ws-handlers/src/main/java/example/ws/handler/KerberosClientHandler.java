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

public class KerberosClientHandler implements SOAPHandler<SOAPMessageContext> {

    final String VALID_CLIENT_NAME = "alice@T41.binas.org";
    final String VALID_SERVER_NAME = "binas@T41.binas.org";
    final int VALID_DURATION = 30;
    public static final String CONTEXT_PROPERTY = "my.property";
    public static final String CONTEXT_PROPERTY2 = "my.property2";

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
        return ClientProcessing(smc, System.out);
    }

    /** The handleFault method is invoked for fault message processing. */
    public boolean handleFault(SOAPMessageContext smc) {
        return ClientProcessing(smc, System.out);
    }

    /**
     * Called at the conclusion of a message exchange pattern just prior to the
     * JAX-WS runtime dispatching a message, fault or exception.
     */
    public void close(MessageContext messageContext) {
        // nothing to clean up 
    }

    private boolean ClientProcessing(SOAPMessageContext smc, PrintStream out) {
        Boolean isRequest = (Boolean) smc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
        int flag = 0;
        if(isRequest){       
            SecureRandom randomGenerator = new SecureRandom();
            Long nounce = randomGenerator.nextLong();
            Key clientKey;
            SessionKey sessionKey;
            CipheredView cipheredTicket=null;
            CipheredView  cipheredAuth=null;
            Auth auth = null;
            Auth authServer = null;
            try{
                KerbyClient client = new KerbyClient("http://sec.sd.rnl.tecnico.ulisboa.pt:8888/kerby");
                clientKey = SecurityHelper.generateKeyFromPassword("YBYDPDWx");
                SessionKeyAndTicketView request = client.requestTicket(VALID_CLIENT_NAME, VALID_SERVER_NAME, nounce, VALID_DURATION);
                CipheredView cypheredkey = request.getSessionKey();
                sessionKey = new SessionKey(cypheredkey,clientKey);
                
                cipheredTicket = request.getTicket();
                
                auth = new Auth(VALID_CLIENT_NAME, new Date());
                cipheredAuth = auth.cipher(sessionKey.getKeyXY());
      
                // get SOAP envelope
                SOAPMessage msg = smc.getMessage();
                SOAPPart sp = msg.getSOAPPart();
                SOAPEnvelope se = sp.getEnvelope();
        
                // add header
                SOAPHeader sh = se.getHeader();
                if (sh == null)
                    sh = se.addHeader();
        
                // add header element (name, namespace prefix, namespace)
                Name ticketName = se.createName("ticket", "t", "http://ticket");
                SOAPHeaderElement element = sh.addHeaderElement(ticketName);
                //element.setValue(Cipheredticket.toString());
                Name authName = se.createName("auth", "t", "http://ticket");
                SOAPHeaderElement element2 = sh.addHeaderElement(authName);
                //element2.setValue(CipheredAuth.toString());

                CipherClerk clerk = new CipherClerk(); 
                CipherClerk clerk2 = new CipherClerk(); 
                Node nodeT = clerk.cipherToXMLNode(cipheredTicket,"ticket");
                Node nodeA = clerk2.cipherToXMLNode(cipheredAuth, "auth");
                
                Node node2 =  element.getOwnerDocument().importNode(nodeT.getFirstChild(),true);
                element.appendChild(node2);
                Node node3 =  element2.getOwnerDocument().importNode(nodeA.getFirstChild(),true);
                element2.appendChild(node3);
                
                Date requestTime = auth.getTimeRequest();

                // put header in a property context
                smc.put(CONTEXT_PROPERTY, requestTime);
                smc.put(CONTEXT_PROPERTY2, sessionKey.getKeyXY());
                // set property scope to application client/server class can
                // access it
                smc.setScope(CONTEXT_PROPERTY, Scope.APPLICATION);
                //smc.setScope(CONTEXT_PROPERTY2, Scope.APPLICATION);

                msg.saveChanges();
            
            }catch(Exception e){
                System.err.println("Caught exception on KerberosClientHandler OUTBOUND : " + e);
                flag = 1;
            }

            if(flag == 1){
                return false;
            }else{
                return true;
            }
        }else{
            try{
                CipheredView rt = null;
                RequestTime requestTimeServer = null;

                // get SOAP envelope
                SOAPMessage msg = smc.getMessage();
                SOAPPart sp = msg.getSOAPPart();
                SOAPEnvelope se = sp.getEnvelope();
                SOAPHeader header = se.getHeader();

                CipherClerk clerk = new CipherClerk(); 

                Node node1 = header.getElementsByTagName("cipheredRt").item(0);
                if(node1 != null){
                    rt = clerk.cipherFromXMLNode(node1);
                }

                Date requestTime = (Date) smc.get(CONTEXT_PROPERTY);
                Key kcs = (Key) smc.get(CONTEXT_PROPERTY2);

                requestTimeServer = new RequestTime(rt, kcs);
                Date rtsd = requestTimeServer.getTimeRequest(); 

                if(rtsd.equals(requestTime)){
                    System.out.println("SERVER AUTHENTICATED");
                }else{
                    System.out.println("UNKNOWN SERVER");
                    throw new RuntimeException();
                }
                
            }catch(Exception e){
                System.err.println("Caught exception on KerberosClientHandler INBOUND : " + e);
                flag = 1;
            }

            if(flag == 1){
                return false;
            }else{
                return true;
            }
        }
    }
}