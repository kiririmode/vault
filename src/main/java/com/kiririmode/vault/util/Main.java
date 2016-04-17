package com.kiririmode.vault.util;

public class Main {

	public static void main(String[] args) throws Exception {
		Vault vault = new KeyStoreVault("/Users/kiririmode/work/keystore/vault.ks", "password", "JCEKS",
				"AES/CBC/PKCS5Padding", "12345678901234567890123456789012", "12345678901234567890123456789012");

		System.out.println(vault.retrieve("test1"));
	}

}
