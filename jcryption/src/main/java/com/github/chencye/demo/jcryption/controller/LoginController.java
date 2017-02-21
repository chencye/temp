package com.github.chencye.demo.jcryption.controller;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

	private static final int KEY_LENGTH = 1024;

	@RequestMapping("getPublickey")
	public String getPublickey(HttpSession session) throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(KEY_LENGTH);
		KeyPair KeyPair = kpg.generateKeyPair();

		session.setAttribute("jCryptionKeys", KeyPair);

		PublicKey publicKey = KeyPair.getPublic();
		/*
		 * publicKey.getEncoded() String n =
		 * publicKey.getModulus().toString(16);
		 * 
		 * String e = publicKey.getPublicExponent().toString(16);
		 * 
		 * int md = getMaxDigits();
		 */
		String response = "{\"publickey\":\""
				+ Base64.encodeBase64String(publicKey.getEncoded()) + "\"}";
		System.out.println(response);
		return response;
	}

	public int getMaxDigits() {
		return KEY_LENGTH * 2 / 16 + 3;
	}

	@RequestMapping("handshake")
	public String handshake(HttpServletRequest request, HttpSession session)
			throws Exception {
		ServletUtils.printParams(request);
		KeyPair keyPair = (KeyPair) session.getAttribute("jCryptionKeys");
		String key = request.getParameter("key");
		System.out.println("handshake的RSA解密前：" + key);
		key = decryptRSA(keyPair, key);
		System.out.println("handshake的RSA解密后：" + key);
		session.setAttribute("jCryptionKey", key);
		String ct = encrypt(key, key);
		System.out.println("handshake的AES加密后：" + ct);
		//System.out.println("handshake的AES解密后：" + new String(decrypt(Base64.decodeBase64(ct.getBytes()), key)));
		String response = "{\"challenge\":\"" + ct + "\"}";
		System.out.println("handshake返回AES加密：" + response);
		return response;
	}

    public static String encrypt(String content, String password) {  
        try {  
            //"AES"：请求的密钥算法的标准名称  
            KeyGenerator kgen = KeyGenerator.getInstance("AES");  
            //256：密钥生成参数；securerandom：密钥生成器的随机源  
            SecureRandom securerandom = new SecureRandom(tohash256Deal(password));  
            kgen.init(256, securerandom);  
            //生成秘密（对称）密钥  
            SecretKey secretKey = kgen.generateKey();  
            //返回基本编码格式的密钥  
            byte[] enCodeFormat = secretKey.getEncoded();  
            //根据给定的字节数组构造一个密钥。enCodeFormat：密钥内容；"AES"：与给定的密钥内容相关联的密钥算法的名称  
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");  
            //将提供程序添加到下一个可用位置  
            Security.addProvider(new BouncyCastleProvider());  
            //创建一个实现指定转换的 Cipher对象，该转换由指定的提供程序提供。  
            //"AES/ECB/PKCS7Padding"：转换的名称；"BC"：提供程序的名称  
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");  
  
            cipher.init(Cipher.ENCRYPT_MODE, key);  
            byte[] byteContent = content.getBytes("utf-8");  
            byte[] cryptograph = cipher.doFinal(byteContent);  
            return Base64.encodeBase64String(cryptograph);  
        } catch (Exception e) {  
            e.printStackTrace();  
        }  
        return null;  
    }  
    private static byte[] tohash256Deal(String datastr) {  
        try {  
            MessageDigest digester=MessageDigest.getInstance("SHA-256");  
            digester.update(datastr.getBytes());  
            byte[] hex=digester.digest();  
            return hex;   
        } catch (NoSuchAlgorithmException e) {  
            throw new RuntimeException(e.getMessage());    
        }  
    }  

	public static byte[] decrypt(byte[] content, String password) throws Exception {
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

	public static String decryptRSA(KeyPair keyPair, String encrypted)
			throws Exception {
		return decryptByPrivateKey(Base64.decodeBase64(encrypted),
				(RSAPrivateKey) keyPair.getPrivate());
	}

	public static String decryptByPrivateKey(byte[] encrypts,
			RSAPrivateKey privateKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		/*
		 * byte[] subBytes = cipher.doFinal(data.substring(0, 127).getBytes());
		 * byte[] subBytes2 = cipher.doFinal(data.substring(127).getBytes());
		 * byte[] bytes = new byte[subBytes.length + subBytes2.length];
		 * System.arraycopy(subBytes, 0, bytes, 0, subBytes.length);
		 * System.arraycopy(subBytes2, 0, bytes, subBytes.length - 1,
		 * subBytes2.length);
		 */
		return new String(cipher.doFinal(encrypts));
	}

}
