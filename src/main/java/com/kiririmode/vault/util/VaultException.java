package com.kiririmode.vault.util;

public class VaultException extends Exception {

	private static final long serialVersionUID = 7125781121519611411L;

	public VaultException(String message) {
		super(message);
	}
	
	public VaultException(String message, Throwable cause) {
		super(message, cause);
	}
}
