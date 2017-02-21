package com.github.chencye.demo.jcryption.controller;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class AESUtils {
	public static String getAESKey(int key_length) {
		String key = null;
		try {
			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			kgen.init(key_length);
			SecretKey skey = kgen.generateKey();
			byte[] raw = skey.getEncoded();
			key = new Base64().encodeAsString(raw);
			System.out.println("------------------Key------------------");
			System.out.println(key);
			System.out.println("--------------End of Key---------------");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return key;
	}

	public static String encrypt(String plaintext, String key, int key_length) {
		String encrypt = null;
		try {

			SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

			byte[] encryptTexts = cipher.doFinal(plaintext.getBytes());

			encrypt = Base64.encodeBase64String(encryptTexts);

			System.out.println("encrypted string:" + encrypt);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return encrypt;
	}

	public static String decrypt(String key, String encrypted) {
		try {
			Key k = new SecretKeySpec(Base64.decodeBase64(key), "AES");
			Cipher c = Cipher.getInstance("AES");
			c.init(Cipher.DECRYPT_MODE, k);
			byte[] decodedValue = Base64.decodeBase64(encrypted);
			byte[] decValue = c.doFinal(decodedValue);
			String decryptedValue = new String(decValue);
			return decryptedValue;
		} catch (IllegalBlockSizeException ex) {
			Logger.getLogger(AESUtils.class.getName()).log(Level.SEVERE, null,
					ex);
		} catch (BadPaddingException ex) {
			Logger.getLogger(AESUtils.class.getName()).log(Level.SEVERE, null,
					ex);
		} catch (InvalidKeyException ex) {
			Logger.getLogger(AESUtils.class.getName()).log(Level.SEVERE, null,
					ex);
		} catch (NoSuchAlgorithmException ex) {
			Logger.getLogger(AESUtils.class.getName()).log(Level.SEVERE, null,
					ex);
		} catch (NoSuchPaddingException ex) {
			Logger.getLogger(AESUtils.class.getName()).log(Level.SEVERE, null,
					ex);
		}
		return null;
	}
}
