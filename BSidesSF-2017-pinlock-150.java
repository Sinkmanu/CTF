/*
 * Challenge:
 * It's the developer's first mobile application. They are trying their hand at storing secrets securely. Could one of them be the flag?
 * 
 * pinstore.apk
 *  
 * 
 * 1. Decompile the apk file.
 * 	1.1	d2j-jar pinstore.apk
 * 	1.2 Examine the code and I look that It's contain a database and the data in the database is encrypted using functions on the application with HARDCODED passwords. (I like jd-gui)
 * 2. Unpack the apk and get the database from "./assets/pinlock.db"
 * 3. The DB has three tables:
 * 	3.1 PinDB: Contains the hash in SHA-1 of the pin (7498). Easy to find on the Internet.
 *			SecretsDBv1: Contains a encrypted message 
 *			SecretsDBv2: Contains a encrypted message (flag)
 * 4. Decrypt the messages using the passwords and the functions used in the apk and get the flag.
 *
 */



import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Bsides {

	
    public static void main(String[] args) {
    	String pin = "7498";																	// PinDB - d8531a519b3d4dfebece0259f90b466a23efc57b (SHA-1)
    	String secret1 = "hcsvUnln5jMdw3GeI4o/txB5vaEf1PFAnKQ3kPsRW2o5rR0a1JE54d0BLkzXPtqB"; 	// SecretsDBv1
    	String secret2 = "Bi528nDlNBcX9BcCC+ZqGQo1Oz01+GOWSmvxRj7jg1g=";						// SecretsDBv2
    	try {
    		byte[] decoded1 = DatatypeConverter.parseBase64Binary(secret1);
    		byte[] decoded2 = DatatypeConverter.parseBase64Binary(secret2);
    		Cipher cipher;
    		cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    		SecretKeySpec key1;
    		key1 = new SecretKeySpec(Arrays.copyOf(MessageDigest.getInstance("SHA-1").digest("t0ps3kr3tk3y".getBytes()), 16), "AES");
    		cipher.init(2, key1);
    		String salida = new String(cipher.doFinal(decoded1), "UTF-8");
    		System.out.println("[*] SecretsDBv1 (encrypted): "+secret1+"\n[*] SecretsDBv1 (decrypted): " + salida);

    		char[] arrayOfChar2 = pin.toCharArray();
    		byte[] paramString = "SampleSalt".getBytes();

    		SecretKeySpec key2 = new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(new PBEKeySpec(arrayOfChar2, paramString, 1000, 128)).getEncoded(), "AES");

    		cipher.init(2, key2);
    		salida = new String(cipher.doFinal(decoded2));
    		System.out.println("[*] SecretsDB2 (encrypted): "+secret2+"\n[+] Flag: "+salida);

    	} catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException e) {
			e.printStackTrace();
		}

        
    }

}
