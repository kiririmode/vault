package com.kiririmode.vault.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.SecretKeyEntry;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class KeyStoreVault implements Vault {

	private String keyStoreUrl;
	private String keyStorePassword;
	private String keyStoreType;
	private String algorithm;
	private String hexEncodedKey;
	private String hexEncodedIv;

	public KeyStoreVault(String keyStoreUrl, String keyStorePassword, String keyStoreType, String algorithm, String hexEncodedKey, String hexEncodedIv) {
		this.keyStoreUrl = keyStoreUrl;
		this.keyStorePassword = keyStorePassword;
		this.keyStoreType = keyStoreType;
		this.algorithm = algorithm;
		this.hexEncodedKey = hexEncodedKey;
		this.hexEncodedIv = hexEncodedIv;
	}
	
	private KeyStore getKeyStore(String keyStoreUrl, String keyStorePassword, String keyStoreType) throws IOException, GeneralSecurityException{
		File keyStoreFile = new File(keyStoreUrl);
		
		try (FileInputStream fis = new FileInputStream(keyStoreFile)) {
			KeyStore ks = KeyStore.getInstance(keyStoreType);
			ks.load(fis, keyStorePassword == null? null : keyStorePassword.toCharArray());
			
			return ks;
		}
	}


	@Override
	public void store(String alias, String secret) throws VaultException {

		try {
			KeyStore ks = getKeyStore(keyStoreUrl, keyStorePassword, keyStoreType);

			Cipher cipher = Cipher.getInstance(algorithm);
			cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(hexEncodedKey), getIv(hexEncodedIv));
			byte[] encryptedSecret = cipher.doFinal(secret.getBytes(StandardCharsets.UTF_8));
			
			SecretKeySpec keySpec = new SecretKeySpec(encryptedSecret, "AES");
			KeyStore.SecretKeyEntry entry = new SecretKeyEntry(keySpec);			
			ks.setEntry(alias, entry, new KeyStore.PasswordProtection(keyStorePassword.toCharArray()));

			try (FileOutputStream fos = new FileOutputStream(keyStoreUrl)) {
				ks.store(fos, keyStorePassword.toCharArray());
			}
		} catch (IOException | GeneralSecurityException e) {
			throw new VaultException(String.format("store failed : keyStore[%s], alias: [%s]", keyStoreUrl, alias), e);
		}
	}

	@Override
	public String retrieve(String alias) throws VaultException {
		try {
			KeyStore ks = getKeyStore(keyStoreUrl, keyStorePassword, keyStoreType);
			KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection(keyStorePassword.toCharArray()));
			byte[] encrypted = secretKeyEntry.getSecretKey().getEncoded();

			Cipher cipher = Cipher.getInstance(algorithm);
			cipher.init(Cipher.DECRYPT_MODE, getSecretKey(hexEncodedKey), getIv(hexEncodedIv));
			byte[] decrypted = cipher.doFinal(encrypted);
			
			return new String(decrypted, StandardCharsets.UTF_8);
		} catch (IOException | GeneralSecurityException e) {
			throw new VaultException(String.format("retrieve failed: keyStore[%s], alias: [%s]", keyStoreUrl, alias), e);
		}
	}
	
    private Key getSecretKey(String hexEncodedKey) {
        return new SecretKeySpec(DatatypeConverter.parseHexBinary(hexEncodedKey), "AES");
    }

    private AlgorithmParameterSpec getIv(String hexEncodedIv) {
        return new IvParameterSpec(DatatypeConverter.parseHexBinary(hexEncodedIv));
    }

}
