import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

public class ADSUserTest {

	@Test
	public void testAddUserToADS() {
		Map<String,String> result = new HashMap<String,String>();
		
		/* set environment */
		String username="uid=admin,ou=system";
		String password="secret";
		String host="codar.poc.de1.cc";
		String portStr="10389";
		
		ADSUser user = new ADSUser();
		result = user.addUserToADS(username, password, host, portStr);
		
		if (result.get("returnResult").length() > 1) fail("Return Result < 0");
		String ret=result.get("returnResult");
		
		System.out.println(result.get("resultMessage"));
		
		/* if connection could be established and all subsequent 
		 * command are working as desired the return value will be 0.
		 */
		assertTrue("could not connect", ret.equals("0"));
	}

}
