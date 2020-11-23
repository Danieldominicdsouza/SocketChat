package com.heyletscode.chattutorial;

import android.util.Base64;

import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Encrypter {

    String AES = "AES";

    public SecretKeySpec generate(String password) throws Exception {
        final MessageDigest messageDigest= MessageDigest.getInstance("SHA-256");
        byte[] bytes = password.getBytes("UTF-8");
        messageDigest.update(bytes, 0,bytes.length);
        byte[] key = messageDigest.digest();
        SecretKeySpec keySpec = new SecretKeySpec(key,"AES");
        return keySpec;
    }

    public String encrypt(String message, String password) throws Exception {
        SecretKeySpec key = generate(password);
        Cipher cipher = Cipher.getInstance(AES);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = cipher.doFinal(message.getBytes());
        final String encryptedMessage = Base64.encodeToString(encVal, Base64.DEFAULT);
        return encryptedMessage;
    }

    public String decrypt(String encryptedMessage, String password) throws Exception {
        SecretKeySpec key = generate(password);
        Cipher cipher = Cipher.getInstance(AES);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodeVal = Base64.decode(encryptedMessage, Base64.DEFAULT);
        byte[] decVal = cipher.doFinal(decodeVal);
        final String decryptedMessage =  new String(decVal);
        return decryptedMessage;
    }
}
