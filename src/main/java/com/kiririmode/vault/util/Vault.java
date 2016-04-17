package com.kiririmode.vault.util;

public interface Vault {

	void store(String key, String secret) throws VaultException;

	String retrieve(String key) throws VaultException;
}
