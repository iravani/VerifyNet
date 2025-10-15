package com.ui.writers.iravani.talebi.crypto.primitives.data.structure;

import java.math.BigInteger;

public class ElGemalEncryptedData {
	public BigInteger c1, c2;

	public ElGemalEncryptedData(BigInteger c1, BigInteger c2) {
		this.c1 = c1;
		this.c2 = c2;
	}
	
	public void print() {
		System.out.println("<" + this.c1 + ", " + this.c2 + ">");
	}
}
