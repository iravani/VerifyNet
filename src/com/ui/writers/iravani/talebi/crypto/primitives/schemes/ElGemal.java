package com.ui.writers.iravani.talebi.crypto.primitives.schemes;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import com.ui.writers.iravani.talebi.crypto.primitives.data.structure.ElGemalEncryptedData;
import com.ui.writers.iravani.talebi.crypto.primitives.data.structure.ElGemalKey;
import com.ui.writers.iravani.talebi.crypto.primitives.data.structure.ElGemalKeyParameters;
import com.ui.writers.iravani.talebi.crypto.primitives.data.structure.ElGemalPublicKey;
import com.ui.writers.iravani.talebi.crypto.primitives.data.structure.ElGemalSecretKey;

public class ElGemal {
	public final ElGemalKey keyPair;
	public final int securityParam;

	public ElGemal(int lamda) {
		this.securityParam = lamda;
		this.keyPair = setupKey(this.securityParam);
	}

	private ElGemalKey setupKey(int securityParam) {
		SecureRandom rand = new SecureRandom();
		BigInteger g = BigInteger.probablePrime(securityParam, rand);
		BigInteger q = BigInteger.probablePrime(securityParam, rand);
		BigInteger x = BigInteger.probablePrime(securityParam, rand);
		BigInteger h = g.modPow(x, q); // (g ^ x) % q

		ElGemalKeyParameters params = new ElGemalKeyParameters(g, q);
		ElGemalPublicKey pk = new ElGemalPublicKey(params, h);
		ElGemalSecretKey sk = new ElGemalSecretKey(params, x);

		return new ElGemalKey(pk, sk);
	}

	public ElGemalEncryptedData Enc(BigInteger m) {
		BigInteger r = BigInteger.probablePrime(securityParam, new Random());
		BigInteger c1 = keyPair.pk.g.modPow(r, keyPair.pk.q);
		BigInteger c2 = m.multiply(keyPair.pk.h.modPow(r, keyPair.pk.q));

		return new ElGemalEncryptedData(c1, c2);
	}

	public BigInteger Dec(ElGemalEncryptedData c) {
		return c.c1.divide(c.c2.modPow(keyPair.sk.x, keyPair.sk.q));
	}
}
