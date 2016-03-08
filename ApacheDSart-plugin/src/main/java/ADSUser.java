import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
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

	@Action(value = "addUserToADS",
			description = "adds a user to the Apache Directory Server",
			outputs = { @Output(OutputNames.RETURN_RESULT) },
			responses = {
				@Response(text = ResponseNames.SUCCESS, field = OutputNames.RETURN_RESULT, value = "0", matchType = MatchType.COMPARE_GREATER_OR_EQUAL, responseType = ResponseType.RESOLVED),
				@Response(text = ResponseNames.FAILURE, field = OutputNames.RETURN_RESULT, value = "0", matchType = MatchType.COMPARE_LESS, responseType = ResponseType.ERROR)
			}
	)
	public Map<String,String> addUserToADS (
			@Param(value = "username") String username,
			@Param(value = "password") String password,
			@Param(value = "host") String host,
			@Param(value = "port") String portStr
			)
	{
		Map<String, String> resultMap = new HashMap<String, String>();
		int port = 10389;  // default port for Apache Directory Server
		
		try {
			port = Integer.valueOf(portStr);
		} catch (Exception e) {
			port = 10389;
		}
			
		LdapConnection connection = new LdapNetworkConnection(host, port);
		try {
			connection.bind(username, password);
		} catch (Exception e) {
			resultMap.put("resultMessage", "server not reachable");
			resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(1));
			return resultMap;
		}
		
		/*
		 * before we return from this step we need to clean up the connection
		 * to the LDAP server
		 */
		try {
			connection.unBind();
			connection.close();
		} catch (LdapException e) {
			resultMap.put("resultMessage", "could not unbind connection to LDAP server");
			resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(0));
		} catch (IOException e) {
			resultMap.put("resultMessage", "could not close connection to LDAP server");
			resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(0));
		}
		
		
		resultMap.put("resultMessage", "server reachable");
		resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(0));
		
		return resultMap;
	}

	public void addUser(String uid, String givenname, String partyid, String password) 

			  throws Exception
			  {
			    String cn = uid;
			    String email = uid; 
			    String sn = givenname; 
			    String usersDn = "uid=" + uid + ",cn=Users,dc=in,dc=example,dc=com";
			    Dn udn = new Dn(usersDn);
			    //getConnection().lookup(udn); -Useful to verify DN
			    DefaultEntry de = new DefaultEntry(
			      udn, // The Dn
			      "objectclass: inetOrgPerson",
			      "objectclass: organizationalPerson",
			      "objectclass: person",
			      "objectclass: fcPerson",
			      "objectclass: top",
			      "cn", cn,
			      "description: Demo user",
			      "givenname", givenname,
			      "mail", email,
			      "preferredlanguage: en",
			      "sn", sn,
			      "uid", uid,
			      "userpassword", password
			    ); 
			    //connection.add(de);
			    System.out.println("Entry addition successful"); 
			  }
}
