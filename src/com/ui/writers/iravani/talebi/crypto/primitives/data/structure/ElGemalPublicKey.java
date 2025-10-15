package com.ui.writers.iravani.talebi.crypto.primitives.data.structure;

import java.math.BigInteger;

public class ElGemalPublicKey {
	public final BigInteger q, g, h;

	public ElGemalPublicKey(BigInteger q, BigInteger g, BigInteger h) {
		this.q = q;
		this.h = h;
		this.g = g;
	}
	
	public ElGemalPublicKey(ElGemalKeyParameters params, BigInteger h) {
		this.q = params.q;
		this.g = params.g;
		this.h = h;
	}
}
