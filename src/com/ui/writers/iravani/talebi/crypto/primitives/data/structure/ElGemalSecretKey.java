package com.ui.writers.iravani.talebi.crypto.primitives.data.structure;

import java.math.BigInteger;

public class ElGemalSecretKey {
	public final BigInteger q, g, x;

	public ElGemalSecretKey(BigInteger q, BigInteger g, BigInteger x) {
		this.q = q;
		this.g = g;
		this.x = x;
	}

	public ElGemalSecretKey(ElGemalKeyParameters params, BigInteger x) {
		this.q = params.q;
		this.g = params.g;
		this.x = x;
	}
}
