import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.exception.LdapException;
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
	 * set up logging first
	 */
	static Logger logger = LoggerFactory.getLogger(ADSUser.class);
	
	/*
	 * first we handle Ldap connections
	 */
	private LdapConnection connection;
	
	 LdapConnection getConnection() {
		 return connection;
	 }
		   
	 void setConnection(LdapConnection connection) {
		 this.connection = connection;
	 }

	 public void connectAndBind(String host, String portStr, String username, String password) throws LdapException, IOException {
		 int port = 10389;  // default port for Apache Directory Server
		 /*
		  * All inputs from an OO step are strings! So we need to convert port 
		  * to an integer. 
		  */
		 try {
			 port = Integer.valueOf(portStr);
		 } catch (Exception e) {
			 port = 10389;
		 }
		 
		 setConnection(new LdapNetworkConnection(host, port));
		 getConnection().bind(username, password);  
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
	 public String encryptPass(String userPassword, LdapSecurityConstants algorithm){
		 
		 byte[] pass = PasswordUtil.createStoragePassword(userPassword, algorithm);
		 return new String(pass, StandardCharsets.UTF_8);
	 }
	 
	  
	 @Action(value = "add entry to Apache DS",
			 description = "adds an object to the Apache Directory Server\n"+
					 		"An object could be an user or a group.\n"+
					 		"\nInputs:\n"+
					 		"objectClasses: comma separated list of objectclass"+
					 		"to add. The objectclass 'top' will be added by default.\n"+
					 		"entries: list of entires to add. Format: key=value;key=value...",
			 outputs = { @Output(OutputNames.RETURN_RESULT) },
			 responses = {
					 @Response(text = ResponseNames.SUCCESS, field = OutputNames.RETURN_RESULT, value = "0", matchType = MatchType.COMPARE_GREATER_OR_EQUAL, responseType = ResponseType.RESOLVED),
					 @Response(text = ResponseNames.FAILURE, field = OutputNames.RETURN_RESULT, value = "0", matchType = MatchType.COMPARE_LESS, responseType = ResponseType.ERROR)
	 }	
	 )	
	 public Map<String,String> addObjectToADS (
			 @Param(value = "username", required = true) String username,
			 @Param(value = "password", encrypted = true) String password,
			 @Param(value = "host", required = true) String host,
			 @Param(value = "port") String port,
			 @Param(value = "DN", required = true) String dn,
			 @Param(value = "objectClasses") String objClasses,
			 @Param(value = "entries") String entries,
			 @Param(value = "userPassword", encrypted = true) String userPassword,
			 @Param(value = "passwordAlg") String lsc
			 )
	 {
		 Map<String, String> resultMap = new HashMap<String, String>();
		 LdapSecurityConstants algorithm = null;
		 String[] objects = objClasses.split(",");
		 
		 if (!lsc.isEmpty()) try {
			 algorithm = LdapSecurityConstants.valueOf(lsc);
		 } catch (Exception e) {
			 logger.info("algorithm not found");
			 resultMap.put("resultMessage", "could not get algorithm");
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(-2));
			 return resultMap;
		 }
		 
		 Dn udn = null;

		 try {
			udn = new Dn(dn);
		} catch (LdapInvalidDnException e) {
			 resultMap.put("resultMessage", "could not get DN");
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(-2));
			 return resultMap;
		}
			
		 /*
		  * connect to LDAP
		  */
		 try {
			 connectAndBind(host, port, username, password);
		 } catch (Exception e) {
			 resultMap.put("resultMessage", "server not reachable");
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(-1));
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
				logger.info("objectclass problem: "+obj);
			}
		 }
		
		 /*
		  * sting is split by ';' and first appearance of '=' because we commas and equal signs
		  */
		 for (String en: entries.split(";")) {
			 try {
				 String key = en.split("=", 2)[0].trim();
				 String value = en.split("=", 2)[1].trim();
				 addEntry(key, value);
			} catch (LdapException e) {
				 logger.info("key value pair problem:\n"+e.getMessage());
			}
		 }
		 
		 /*
		  * if necessary encrypt password with algorithm
		  */
		 if (!userPassword.isEmpty()) {
			 try {
				 if (lsc.isEmpty()) {
					 addEntry("userPassword", userPassword);
				 } else {
					 addEntry("userPassword", encryptPass(userPassword, algorithm));
				 }
			 } catch (LdapException e) {
				 System.out.println("could not add password properly");
				 e.printStackTrace();
			 }
		 }
		
		try {
			getConnection().add(getEntry());
		} catch (LdapException e) {
			resultMap.put("resultMessage", "could not add entry to server");
			resultMap.put("addMessage", e.getMessage());
			resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(-4));
			return resultMap;
		}
		 
		 /*
		  * before we return from this step we need to clean up the connection
		  * to the LDAP server
		  */
		 try {
			 close();
		 } catch (LdapException e) {
			 logger.info("could not close connection to Ldap server: "+host);
			 resultMap.put("resultMessage", "could not unbind connection to LDAP server");
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(-1));
			 return resultMap;
		 } catch (IOException e) {
			 resultMap.put("resultMessage", "could not close connection to LDAP server");
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(-1));
			 return resultMap;
		 }
		 
		
		 resultMap.put("resultMessage", getEntry().toString());
		 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(0));
		
		 return resultMap;
	 }
	 
	 
	 @Action(value = "change entry in Apache DS",
			 description = "changes attributes of an object in Apache Directory Server\n",
			 outputs = { @Output(OutputNames.RETURN_RESULT),
					 @Output("resultMessage") 
			 },
			 responses = {
					 @Response(text = ResponseNames.SUCCESS, field = OutputNames.RETURN_RESULT, value = "0", matchType = MatchType.COMPARE_GREATER_OR_EQUAL, responseType = ResponseType.RESOLVED),
					 @Response(text = ResponseNames.FAILURE, field = OutputNames.RETURN_RESULT, value = "0", matchType = MatchType.COMPARE_LESS, responseType = ResponseType.ERROR)
	 		 }	
	 )	
	 public Map<String,String> changeObjectInADS(
			 @Param(value = "username", required = true) String username,
			 @Param(value = "password", encrypted = true) String password,
			 @Param(value = "host", required = true) String host,
			 @Param(value = "port") String port,
			 @Param(value = "DN", required = true) String dn,
			 @Param(value = "modify") String modifyStr,
			 @Param(value = "userPassword", encrypted = true) String userPassword,
			 @Param(value = "passwordAlg") String lsc
			 ) 
	 {
		 Map <String,String> resultMap = new HashMap<String,String>();
		
		 LdapSecurityConstants algorithm = null;
		 
		 if (!lsc.isEmpty()) try {
			 algorithm = LdapSecurityConstants.valueOf(lsc);
		 } catch (Exception e) {
			 logger.info("algorithm not found");
			 resultMap.put("resultMessage", "could not get algorithm");
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(-2));
			 return resultMap;
		 }
		 
		 /*
		  * connect to LDAP
		  */
		 try {
			 connectAndBind(host, port, username, password);
		 } catch (Exception e) {
			 resultMap.put("resultMessage", "server not reachable");
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(-1));
			 return resultMap;
		 }

				 
		 /*
		  * we need to look for the changes here.
		  * format:
		  * ADD: key, value
		  * REPLACE: key, value
		  * REMOVE: key
		  * 
		  * The replace function is not aware of multiple entries!
		  */
		 Map<String,Modification> mod = new HashMap<String,Modification>();
		 Integer item = 0;
		 for (String en: modifyStr.split(";")) {
			 try {
				 String change = en.split(":")[0].toUpperCase().trim();
				 String keyvalue = en.split(":")[1].trim();
				 
				 String key = keyvalue.split("=", 2)[0];
				 String value = keyvalue.split("=", 2)[1];
	
				 /*
				  * if the change keyword (i.e. add, replace, remove) was
				  * not found than nothing will be put on the hashmap!
				  */
				 
				 if (change.equals("ADD")) {
					Modification add = new DefaultModification(ModificationOperation.ADD_ATTRIBUTE, key, value);
					mod.put(item.toString(), add);
				 }
				 if (change.equals("REPLACE")) {
					Modification replace = new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, key, value);
					mod.put(item.toString(), replace);
				 }
				 if (change.equals("REMOVE")) {
					Modification remove = new DefaultModification(ModificationOperation.REMOVE_ATTRIBUTE, key, value);
					mod.put(item.toString(), remove);
				 }
				 item++;
			} catch (Exception e) {
				 logger.info("key value pair problem:\n"+e.getMessage());
			}
		 } 
		 
		 if (!userPassword.isEmpty()) {
			 if (!lsc.isEmpty()) {
				 userPassword = encryptPass(userPassword, algorithm);
			 }
			 
			 try {
					Modification changePasswd = new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "userPassword", userPassword);
					mod.put("passwd", changePasswd);
			 } catch (Exception e) {
				 logger.info("key value pair problem:\n"+e.getMessage());
			 }
		 } 
		 
		 /*
		  * put all entries into a Modification list so that all entries can
		  * be submitted once. this is important because Apache DS handles
		  * data consistency.
		  */
		 Modification[] values = new Modification[mod.size()];
		 int index = 0;
		 for (Map.Entry<String, Modification> value: mod.entrySet()){
			 values[index++] = value.getValue();
		 }
		 
		 /*
		  * make the changes to Apache DS now!
		  */
		 try {
			 getConnection().modify(dn, values);
		} catch (LdapException e) {
			 resultMap.put("resultMessage", "could not apply changes");
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(-4));
			 return resultMap;
		}
		 
		 Entry entry = null;
		 try {
			entry = getConnection().lookup(dn);
			resultMap.put("resultMessage", entry.toString());
		 } catch (Exception e) {
			logger.info("could not lookup dn "+dn);
			resultMap.put("resultMessage", "entry changed");
		 }
		 
		 /*
		  * before we return from this step we need to clean up the connection
		  * to the LDAP server
		  */
		 try {
			 close();
		 } catch (LdapException e) {
			 logger.info("could not close connection to Ldap server: "+host);
			 resultMap.put("resultMessage", "could not unbind connection to LDAP server");
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(-1));
			 return resultMap;
		 } catch (IOException e) {
			 resultMap.put("resultMessage", "could not close connection to LDAP server");
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(-1));
			 return resultMap;
		 }
		 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(0));
		
		 return resultMap;
	 }
	 
	 @Action(value = "lookup entry in Apache DS",
			 description = "returns an entry in the Apache Directory Server\n",
			 outputs = { @Output(OutputNames.RETURN_RESULT),
					     @Output("entry"),
					     @Output("resultMessage")
			 },
			 responses = {
					 @Response(text = ResponseNames.SUCCESS, field = OutputNames.RETURN_RESULT, value = "0", matchType = MatchType.COMPARE_GREATER_OR_EQUAL, responseType = ResponseType.RESOLVED),
					 @Response(text = ResponseNames.FAILURE, field = OutputNames.RETURN_RESULT, value = "0", matchType = MatchType.COMPARE_LESS, responseType = ResponseType.ERROR)
	 		 }	
	 )	
	 public Map<String,String> lookupObjectInADS(
			 @Param(value = "username", required = true) String username,
			 @Param(value = "password", encrypted = true) String password,
			 @Param(value = "host", required = true) String host,
			 @Param(value = "port") String port,
			 @Param(value = "DN", required = true) String dn)
	 {
		 Map <String,String> resultMap = new HashMap<String,String>();
			
		 /*
		  * connect to LDAP
		  */
		 try {
			 connectAndBind(host, port, username, password);
		 } catch (Exception e) {
			 resultMap.put("resultMessage", "server not reachable");
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(-3));
			 return resultMap;
		 }
		 
		 Entry entry = null;
		 try {
			entry = getConnection().lookup(dn);
			resultMap.put("entry", entry.toString());
			resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(0));
			
		 } catch (Exception e) {
			logger.info("could not lookup dn "+dn);
			resultMap.put("resultMessage", "entry not found");
			resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(-1));
			
		 }
	
		 /*
		  * before we return from this step we need to clean up the connection
		  * to the LDAP server
		  */
		 try {
			 close();
		 } catch (LdapException e) {
			 logger.info("could not close connection to Ldap server: "+host);
			 resultMap.put("resultMessage", "could not unbind connection to LDAP server");
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(1));
			 return resultMap;
		 } catch (IOException e) {
			 resultMap.put("resultMessage", "could not close connection to LDAP server");
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(1));
			 return resultMap;
		 }
		 
		 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(0));
		
		 return resultMap;
	 }
	 
	 @Action(value = "delete entry in Apache DS",
			 description = "deletes an object in the Apache Directory Server\n",
			 outputs = { @Output(OutputNames.RETURN_RESULT),
					     @Output("resultMessage")
			 },
			 responses = {
					 @Response(text = ResponseNames.SUCCESS, field = OutputNames.RETURN_RESULT, value = "0", matchType = MatchType.COMPARE_GREATER_OR_EQUAL, responseType = ResponseType.RESOLVED),
					 @Response(text = ResponseNames.FAILURE, field = OutputNames.RETURN_RESULT, value = "0", matchType = MatchType.COMPARE_LESS, responseType = ResponseType.ERROR)
	 		 }	
	 )	
	 public Map<String,String> deleteObjectInADS(
			 @Param(value = "username", required = true) String username,
			 @Param(value = "password", encrypted = true) String password,
			 @Param(value = "host", required = true) String host,
			 @Param(value = "port") String port,
			 @Param(value = "DN", required = true) String dn)
	 {
		 Map <String,String> resultMap = new HashMap<String,String>();
			
		 /*
		  * connect to LDAP
		  */
		 try {
			 connectAndBind(host, port, username, password);
		 } catch (Exception e) {
			 resultMap.put("resultMessage", "server not reachable");
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(-3));
			 return resultMap;
		 }
		 
		 try {
			getConnection().delete(dn);
		} catch (LdapException e1) {
			 logger.info("could not delete dn: "+dn);
			 resultMap.put("resultMessage", "could not delete dn: "+dn);
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(-2));
			 return resultMap;
		}
		 
		 /*
		  * before we return from this step we need to clean up the connection
		  * to the LDAP server
		  */
		 try {
			 close();
		 } catch (LdapException e) {
			 logger.info("could not close connection to Ldap server: "+host);
			 resultMap.put("resultMessage", "could not unbind connection to LDAP server");
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(-1));
			 return resultMap;
		 } catch (IOException e) {
			 resultMap.put("resultMessage", "could not close connection to LDAP server");
			 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(-1));
			 return resultMap;
		 }
		 resultMap.put("resultMessage", "Entry deleted");
		 resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(0));
		
		 return resultMap;
	 }
}

