import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.password.PasswordUtil;
import org.apache.directory.api.ldap.model.constants.LdapSecurityConstants;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;


import com.hp.oo.sdk.content.annotations.Action;
import com.hp.oo.sdk.content.annotations.Output;
import com.hp.oo.sdk.content.annotations.Param;
import com.hp.oo.sdk.content.annotations.Response;
import com.hp.oo.sdk.content.constants.OutputNames;
import com.hp.oo.sdk.content.constants.ResponseNames;
import com.hp.oo.sdk.content.plugin.ActionMetadata.MatchType;
import com.hp.oo.sdk.content.plugin.ActionMetadata.ResponseType;

public class ADSUser {

	/*
	 * firt we handle Ldap connections
	 */
	private LdapConnection connection;
	
	 LdapConnection getConnection() {
		 return connection;
	 }
		   
	 void setConnection(LdapConnection connection) {
		 this.connection = connection;
	 }

	 public void connectAndBind(String host, int port, String username, String password) throws LdapException, IOException {
		 setConnection(new LdapNetworkConnection(host, port));
		 getConnection().bind(username, password);  
	 }

	 public void unbind() throws LdapException {
		 getConnection().unBind();
	 }

	 public void close() throws IOException, LdapException {
		 getConnection().unBind();
		 getConnection().close();
	 }	
	
	 /*
	  * now we handle Ldap entries and organize them
	  */
	 private DefaultEntry de;
	 
	 public void setEntry(DefaultEntry de) {
		 this.de = de;
	 }
	 
	 public DefaultEntry getEntry() {
		 return this.de;
	 }
	 
	 public void newEntry(Dn dn)
	 {
		DefaultEntry de;
		try {
			de = new DefaultEntry(dn, "objectclass: top");
		} catch (LdapException e) {
			return;
		}
		
		this.setEntry(de);
	 }
	 
	 public void addEntry(String attr, String value) throws LdapException {
		 getEntry().add(attr, value);
	 }
	 
	 
	 /*
	  * encrypt the users password
	  */
	 public String encryptPass(String userPassword, LdapSecurityConstants algorythm){
		 
		 byte[] pass = PasswordUtil.createStoragePassword(userPassword, algorythm);
		 return new String(pass, StandardCharsets.UTF_8);
	 }
	 
	  
	 @Action(value = "addUserToADS",
			 description = "adds a user to the Apache Directory Server",
			 outputs = { @Output(OutputNames.RETURN_RESULT) },
			 responses = {
					 @Response(text = ResponseNames.SUCCESS, field = OutputNames.RETURN_RESULT, value = "0", matchType = MatchType.COMPARE_GREATER_OR_EQUAL, responseType = ResponseType.RESOLVED),
					 @Response(text = ResponseNames.FAILURE, field = OutputNames.RETURN_RESULT, value = "0", matchType = MatchType.COMPARE_LESS, responseType = ResponseType.ERROR)
	 }	
	 )	
	 public Map<String,String> addUserToADS (
			 @Param(value = "username", required = true) String username,
			 @Param(value = "password", encrypted = true) String password,
			 @Param(value = "host", required = true) String host,
			 @Param(value = "port") String portStr,
			 @Param(value = "DN", required = true) String dn,
			 @Param(value = "objectClasses") String objClasses,
			 @Param(value = "entries") String entries,
			 @Param(value = "userPassword", encrypted = true) String userPassword,
			 @Param(value = "passwordAlg") String lsc
			 )
	 {
		 Map<String, String> resultMap = new HashMap<String, String>();
		 int port = 10389;  // default port for Apache Directory Server
		 LdapSecurityConstants algorythm = LdapSecurityConstants.valueOf(lsc);
		 String[] objects = objClasses.split(",");
		 
		 Dn udn = null;

		 try {
			udn = new Dn(dn);
		} catch (LdapInvalidDnException e) {
			 resultMap.put("resultMessage", "could not get DN");
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(2));
			 return resultMap;
		}
		
		 /*
		  * All inputs from an OO step are strings! So we need to convert port 
		  * to an integer. 
		  */
		 try {
			 port = Integer.valueOf(portStr);
		 } catch (Exception e) {
			 port = 10389;
		 }
			
		 /*
		  * connect to LDAP
		  */
		 try {
			 connectAndBind(host, port, username, password);
		 } catch (Exception e) {
			 resultMap.put("resultMessage", "server not reachable");
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(1));
			 return resultMap;
		 }
		 
		 /*
		  * here we start our main code!
		  */
		 
		 newEntry(udn);
		 
		 for(String obj: objects) {
			 try {
				addEntry("objectclass", obj);
			} catch (LdapException e) {
				/* do nothing */
			}
		 }
		
		 for (String en: entries.split(";")) {
			 String key = en.split("=")[0];
			 String value = en.split("=")[1];
			 try {
				addEntry(key, value);
			} catch (LdapException e) {
				/* do nothing */
			}
		 }
		 
		 if (!userPassword.isEmpty()) {
			 try {
				 if (lsc.isEmpty()) {
					 algorythm = LdapSecurityConstants.HASH_METHOD_SHA;
				 }
				 addEntry("userPassword", encryptPass(userPassword, algorythm));
			 } catch (LdapException e) {
				 System.out.println("could not add password properly");
				 e.printStackTrace();
			 }
		 }
		 
		try {
			getConnection().add(getEntry());
		} catch (LdapException e1) {
			resultMap.put("resultMessage", "could not add entry to server");
			resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(4));
			return resultMap;
		}
		 
		 /*
		  * before we return from this step we need to clean up the connection
		  * to the LDAP server
		  */
		 try {
			 getConnection().unBind();
			 getConnection().close();
		 } catch (LdapException e) {
			 resultMap.put("resultMessage", "could not unbind connection to LDAP server");
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(1));
			 return resultMap;
		 } catch (IOException e) {
			 resultMap.put("resultMessage", "could not close connection to LDAP server");
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(1));
			 return resultMap;
		 }
		
		
		 resultMap.put("resultMessage", "server reachable");
		 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(0));
		
		 return resultMap;
	 }
}
