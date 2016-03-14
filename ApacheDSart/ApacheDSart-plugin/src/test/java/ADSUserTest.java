import static org.junit.Assert.*;
import org.junit.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.apache.directory.api.ldap.model.constants.LdapSecurityConstants;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.password.PasswordUtil;


public class ADSUserTest {
	
	/* set environment */
	String username="uid=admin,ou=system";
	String password="secret";
	String host="codar.poc.de1.cc";
	String portStr="10389";
	String groupDn="cn=OOTestGroup,ou=CODARProjects,dc=example,dc=com";
	String groupObjects="groupOfNames";
	String groupEntries = "cn=OOTestGroup;member=uid=markus,ou=CSAUsers,dc=example,dc=com";
	String uid = "markus";
	String dn = "uid="+uid+",ou=CSAUsers,dc=example,dc=com";
	String objects = "inetOrgPerson,Person,organizationalPerson,extensibleObject";
	String entries = "uid="+uid+";cn=markus;sn=Markus";
	String userPassword = "cloud"; // "{SHA}AA55PbcMWTCfpvDzbQBG0RDzvjw=";
	LdapSecurityConstants lsc = LdapSecurityConstants.HASH_METHOD_SHA;
	
	/* this boolean variable decides if we need to insist write an object
	 * to ldap. if set to true it will not require it.
	 */
	boolean lazy = true;
	

	@Test
	public void testAddUserToADS() {
		Map<String,String> result = new HashMap<String,String>();
		String lscString = "";
		
		if (lsc != null) lscString = lsc.toString();
		
		ADSUser user = new ADSUser();
		result = user.addObjectToADS(username, password, host, portStr, 
					dn, objects, entries, userPassword, lscString);
		
		if (result.get("returnResult").length() < 0) fail("Return Result < 0");
		String ret=result.get("returnResult");
			
		/* if connection could be established and all subsequent 
		 * command are working as desired the return value will be 0.
		 */
		
		/*
		 * if lazy is true we can skip to write the object to ldap.
		 * returnResult 4 means that only writing back did not work, 
		 * probably because it alredy exists.  
		 */
		if (lazy) {
			assertTrue("Error message: "+result.get("resultMessage"), 
					ret.equals("0") || ret.equals("-4"));
		} else {
			assertTrue("Error message: "+result.get("resultMessage"), ret.equals("0"));
		}
	}

	@Test
	public void testAddGroupToADS() {
		Map<String,String> result = new HashMap<String,String>();
		
		ADSUser user = new ADSUser();
		result = user.addObjectToADS(username, password, host, portStr, 
					groupDn, groupObjects, groupEntries, "" /* userpassword*/ , "" /* algorithm */);
		
		if (result.get("returnResult").length() < 0) fail("Return Result < 0");
		String ret=result.get("returnResult");
			
		/* if connection could be established and all subsequent 
		 * command are working as desired the return value will be 0.
		 */
		
		/*
		 * if lazy is true we can skip to write the object to ldap.
		 * returnResult 4 means that only writing back did not work, 
		 * probably because it alredy exists.  
		 */
		if (lazy) {
			assertTrue("Error message: "+result.get("resultMessage"), 
					ret.equals("0") || ret.equals("-4"));
		} else {
			assertTrue("Error message: "+result.get("resultMessage"), ret.equals("0"));
		}
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
			System.out.println("cannot convert string portStr to integer");
		}
		
		ADSUser user = new ADSUser();
		
		try {
			user.connectAndBind(host, port, username, password);
		} catch (LdapException e) {
			fail("connection to Ldap could not be established");
		} catch (IOException e) {
			fail("connction to Ldap has IO problems");
		}
		
		assertTrue("could not get connection", user.getConnection().isConnected());
		
		try {
			user.getConnection().unBind();
			user.getConnection().close();
		} catch (IOException e) {
			fail("IO exception");
		} catch (LdapException e) {
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
		 * check if there is anything to do
		 */
		if (userPassword.isEmpty()) return;
		
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
	
	@Test
	public void testDeleteObject()
	{
		Map<String,String> result = new HashMap<String,String>();
		ADSUser user = new ADSUser();

		String uid = "deleteUser";
		String dn = "uid="+uid+",ou=CSAUsers,dc=example,dc=com";
		String objects = "inetOrgPerson,Person,organizationalPerson,extensibleObject";
		String entries = "uid="+uid+";cn=PleaseDelete;sn=PleaseDelete";
		String userPassword = "cloud"; // "{SHA}AA55PbcMWTCfpvDzbQBG0RDzvjw=";
		LdapSecurityConstants lsc = LdapSecurityConstants.HASH_METHOD_SHA;
		
		result = user.addObjectToADS(username, password, host, portStr, 
					dn, objects, entries, userPassword , lsc.toString());
		
		/*
		 * add object just to delete it in the next step
		 */
		assertTrue("user could not be initialized to test function 'deleteObject'",
				result.get("returnResult").equals("0"));
	
		/*
		 * delete the object. This is the main test!
		 */
		result = user.deleteObjectinADS(username, password, host, portStr, dn);
		assertTrue("object could not be deleted", result.get("returnResult").equals("0"));
	}
	
	@Test
	public void testChangeObject()
	{
		Map<String,String> result = new HashMap<String,String>();
		ADSUser user = new ADSUser();

		String uid = "changeUser";
		String dn = "uid="+uid+",ou=CSAUsers,dc=example,dc=com";
		String objects = "inetOrgPerson,Person,organizationalPerson,extensibleObject";
		String entries = "cn=PleaseChange;sn=PleaseChange";
		String userPassword = "cloud"; // "{SHA}AA55PbcMWTCfpvDzbQBG0RDzvjw=";
		LdapSecurityConstants lsc = LdapSecurityConstants.HASH_METHOD_MD5;
		String modifyStr = "ADD: emailAddress=test@poc.de1.cc; ADD: info=test";
		
		/*
		 * add object just to delete it in the next step
		 */
		result = user.addObjectToADS(username, password, host, portStr, 
					dn, objects, entries, userPassword , lsc.toString());
		
		assertTrue("user could not be initialized to test function 'deleteObject'",
				result.get("returnResult").equals("0"));

		result = user.changeObjectInADS(username, password, host, portStr, dn, modifyStr, "", "");
		assertTrue("could not change attribute",
				result.get("returnResult").equals("0"));
		
		modifyStr = "REPLACE: cn=changed; REPLACE: emailAddress=done@poc.de1.cc";
		result = user.changeObjectInADS(username, password, host, portStr, dn, modifyStr, "test", lsc.toString());
		assertTrue("could not change attribute",
				result.get("returnResult").equals("0"));
		
		/*
		 * clean up: delete user again
		 */
		result = user.deleteObjectinADS(username, password, host, portStr, dn);
		assertTrue("could not delete user",
				result.get("returnResult").equals("0"));
	}
}
