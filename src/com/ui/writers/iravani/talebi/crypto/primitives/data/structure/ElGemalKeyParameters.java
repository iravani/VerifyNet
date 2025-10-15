package com.ui.writers.iravani.talebi.crypto.primitives.data.structure;

import java.math.BigInteger;

public class ElGemalKeyParameters {
	public final BigInteger g, q;

	public ElGemalKeyParameters(BigInteger g, BigInteger q) {
		this.g = g;
		this.q = q;
	}
}
