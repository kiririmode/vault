package com.kiririmode.vault.util;

public class Main {
	
	public static void main(String[] args) throws Exception {
		Vault vault = new KeyStoreVault("/Users/kiririmode/work/keystore/vault.ks", "password", "JCEKS", "password");
		
		vault.store("test1", "test1 secret");
		System.out.println(vault.retrieve("test1"));
	}

}
