package com.ui.writers.iravani.talebi.crypto.primitives.schemes;

import java.math.BigInteger;

public class BilinearPairing {
	private BigInteger g1, g2, q;

	public BilinearPairing(BigInteger g1, BigInteger g2, BigInteger q) {
		this.g1 = g1;
		this.g2 = g2;
		this.q = q;
	}
	
	public BigInteger e(BigInteger p1, BigInteger p2) {
		return p1.modPow(p2, q);
	}
}
