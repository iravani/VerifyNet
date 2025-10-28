package com.ui.writers.iravani.talebi.crypto.primitives.schemes;

import java.math.BigInteger;
import java.security.SecureRandom;

import com.ui.writers.iravani.talebi.crypto.primitives.data.structure.HashTupple;

public class HomomorphicHash {
	private final SecureRandom rand = new SecureRandom();

    private int lamda;

    private final BigInteger q;
    private final BigInteger g;
    
    private BigInteger h;
    
    public HomomorphicHash(int lamda, BigInteger g, BigInteger q) {
    	this.lamda = lamda;
    	this.q = q;
    	this.g = g;
    	
    	var r = BigInteger.probablePrime(this.lamda, rand);
    	this.h = g.modPow(r, q);
    }
    
    public HashTupple hash(BigInteger m) {
        return new HashTupple(g.modPow(m, q), h.modPow(m, q));
    }
    
    public HashTupple addHashes(HashTupple hash1, HashTupple hash2) {
        return new HashTupple(hash1.h1.multiply(hash2.h1).mod(q), hash1.h2.multiply(hash2.h2).mod(q));
    }
    
    public HashTupple multiplyHashes(HashTupple hash1, HashTupple hash2) {
        return new HashTupple(hash1.h1.modPow(hash2.h1, q), hash1.h2.modPow(hash2.h2, q));
    }
}
