package com.ui.writers.iravani.talebi.crypto.primitives.data.structure;


public class ElGemalKey {
	public final ElGemalPublicKey pk;
	public final ElGemalSecretKey sk;
	
	public ElGemalKey(ElGemalPublicKey pk, ElGemalSecretKey sk) {
		this.sk = sk;
		this.pk = pk;
	}
}
