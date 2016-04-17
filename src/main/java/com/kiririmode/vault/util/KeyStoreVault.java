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

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyStoreVault implements Vault {

	private String keyStoreUrl;
	private String keyStorePassword;
	private String keyStoreType;
	private String algorithm;

	public KeyStoreVault(String keyStoreUrl, String keyStorePassword, String keyStoreType, String algorithm) {
		this.keyStoreUrl = keyStoreUrl;
		this.keyStorePassword = keyStorePassword;
		this.keyStoreType = keyStoreType;
		this.algorithm = algorithm;
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

			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBE");
			SecretKey secretKey = factory.generateSecret(new PBEKeySpec(secret.toCharArray()));			
			KeyStore.SecretKeyEntry entry = new SecretKeyEntry(secretKey);

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

			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBE");
			PBEKeySpec keySpec = (PBEKeySpec)factory.getKeySpec(secretKeyEntry.getSecretKey(), PBEKeySpec.class);
			
			return new String(keySpec.getPassword());
		} catch (IOException | GeneralSecurityException e) {
			throw new VaultException(String.format("retrieve failed: keyStore[%s], alias: [%s]", keyStoreUrl, alias), e);
		}
	}

}
