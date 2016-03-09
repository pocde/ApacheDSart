import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import org.apache.directory.api.ldap.model.constants.LdapSecurityConstants;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.password.PasswordUtil;
import org.junit.Test;

public class ADSUserTest {
	
	/* set environment */
	String username="uid=admin,ou=system";
	String password="secret";
	String host="codar.poc.de1.cc";
	String portStr="10389";
	String uid = "markus";
	String dn = "uid="+uid+",ou=CSAUsers,dc=example,dc=com";
	String objects = "inetOrgPerson,Person,organizationalPerson,extensibleObject";
	String entries = "uid="+uid+";cn=markus;sn=Markus";
	String userPassword = "cloud"; // "{SHA}AA55PbcMWTCfpvDzbQBG0RDzvjw="; // cloud
	LdapSecurityConstants lsc = LdapSecurityConstants.HASH_METHOD_SHA;
	

	@Test
	public void testAddUserToADS() {
		Map<String,String> result = new HashMap<String,String>();

		ADSUser user = new ADSUser();
		result = user.addUserToADS(username, password, host, portStr, 
					dn, objects, entries, userPassword, lsc.toString());
		
		if (result.get("returnResult").length() > 1) fail("Return Result < 0");
		String ret=result.get("returnResult");
		
		// System.out.println("Return message: "+result.get("resultMessage"));
		
		/* if connection could be established and all subsequent 
		 * command are working as desired the return value will be 0.
		 */
		assertTrue("could not connect", ret.equals("0"));
	}
	
	/*
	 * the following test only tests if a connection to the LDAP server
	 * can be established and closed again. There is no further test
	 * included.
	 */
	@Test
	public void testLdapConnection() {
		int port=10389;
		
		try {
			port=Integer.valueOf(portStr);
		} catch (Exception e) {
			/* do nothing */
		}
		
		ADSUser user = new ADSUser();
		
		try {
			user.connectAndBind(host, port, username, password);
		} catch (LdapException | IOException e) {
			fail("connection to Ldap could not be established");
		}
		
		assertTrue("could not get connection", user.getConnection().isConnected());
		
		try {
			user.getConnection().unBind();
			user.getConnection().close();
		} catch (IOException | LdapException e) {
			fail("closing Ldap connection failed.");
		}
		
		assertFalse("could not close connection", user.getConnection().isConnected());
	}
	
	/*
	 * test objects in Ldap. Create an entry and then add an object.
	 */
	@Test
	public void testObjectEntries() {
		ADSUser user = new ADSUser();
		Dn udn = null;
		
		try {
			udn = new Dn(dn);
		} catch (LdapInvalidDnException e) {
			fail("could not create DN");
		}
		
		user.newEntry(udn);
		
		assertTrue("could not create entry", user.getEntry().getDn().equals(udn));
		
		try {
			user.addEntry("objectclass", "inetOrgPerson");
		} catch (LdapException e) {
			fail("could not add entry 'inetOrgPerson'");
		}
		
		assertTrue("could not add entry 'inetOrgPerson'", 
				user.getEntry().contains("objectclass", "inetOrgPerson"));
	}
	
	@Test
	public void testEncryption()
	{
		ADSUser user = new ADSUser();
		
		/*
		 * this test will use a password, encrypt it with a algorythm. The result is then
		 * used to check if the password was encrypted by the given algorythm.
		 * At the end we make use of an Ldap method to see if the original password
		 * matches the encrypted one.
		 */
		
		byte[] pass = user.encryptPass(userPassword, lsc).getBytes();
		
		assertTrue("password encryption did not work", 
				PasswordUtil.findAlgorithm(pass).equals(lsc));
		
		assertTrue("passwords are not the same",
				PasswordUtil.compareCredentials(userPassword.getBytes(), pass));
	}

}
