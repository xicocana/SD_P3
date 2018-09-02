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

public class AtackerHandler implements SOAPHandler<SOAPMessageContext> {

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
        AtackerProcessing(smc, System.out);
        return true;
    }

    /** The handleFault method is invoked for fault message processing. */
    public boolean handleFault(SOAPMessageContext smc) {
        AtackerProcessing(smc, System.out);
        return true;
    }

    /**
     * Called at the conclusion of a message exchange pattern just prior to the
     * JAX-WS runtime dispatching a message, fault or exception.
     */
    public void close(MessageContext messageContext) {
        // nothing to clean up 
    }

    private void AtackerProcessing(SOAPMessageContext smc, PrintStream out) {
        Boolean isRequest = (Boolean) smc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
        if(isRequest){       
            try{
                //get SOAP envelope
                SOAPMessage msg = smc.getMessage();
                SOAPPart sp = msg.getSOAPPart();
                SOAPEnvelope se = sp.getEnvelope();
                SOAPHeader header = se.getHeader();
                SOAPBody body = se.getBody();

                Name name = se.createName("atack", "a", "http://atack");
                SOAPBodyElement element = body.addBodyElement(name);

                element.addTextNode("corrupted soap message");

                msg.saveChanges();
            
            }catch(Exception e){
                System.out.println("attacker does not possess the necessary skills...");
            }
        }
    }
}