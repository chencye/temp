package com.github.chencye.demo.jcryption.controller;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class Test {
	
	public static void main(String[] args) throws Exception {
		String pwd = "67e80cd74486f66df6aa2e35150553db22a115be66e696df2e9c21c9bcb1c75a";
		byte[] en = encrypt(pwd, pwd, 128);
		System.out.println(Base64.encodeBase64String(en));
		System.out.println(new String(decrypt(en, pwd)));
	}
	
	public static byte[] encrypt(String plaintext, String password,
			int key_length) throws Exception {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(key_length, new SecureRandom(password.getBytes()));
		SecretKey secretKey = kgen.generateKey();
		byte[] enCodeFormat = secretKey.getEncoded();
		SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
		Cipher cipher = Cipher.getInstance("AES");// 创建密码器
		byte[] byteContent = plaintext.getBytes();
		cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化
		byte[] result = cipher.doFinal(byteContent);
		return result; // 加密
	}

	public static byte[] decrypt(byte[] content, String password)
			throws Exception {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(128, new SecureRandom(password.getBytes()));
		SecretKey secretKey = kgen.generateKey();
		byte[] enCodeFormat = secretKey.getEncoded();
		SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
		Cipher cipher = Cipher.getInstance("AES");// 创建密码器
		cipher.init(Cipher.DECRYPT_MODE, key);// 初始化
		byte[] result = cipher.doFinal(content);
		return result; // 加密
	}
}
