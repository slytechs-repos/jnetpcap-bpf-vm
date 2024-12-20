package com.slytechs.jnet.platform.jnpl.vm.api;

/**
 * Base exception for BPF VM extensions.
 */
public class ExtensionException extends Exception {

	private static final long serialVersionUID = 1L;

	/**
	 * Creates a new extension exception.
	 * 
	 * @param message Error message
	 */
	public ExtensionException(String message) {
		super(message);
	}

	/**
	 * Creates a new extension exception with cause.
	 * 
	 * @param message Error message
	 * @param cause   Error cause
	 */
	public ExtensionException(String message, Throwable cause) {
		super(message, cause);
	}
}