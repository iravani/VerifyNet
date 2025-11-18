import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {
	public static final int LAMDA = 32;
	static SecureRandom sRand = new SecureRandom();
	// پارامترهای عمومی
	public static final BigInteger g = BigInteger.valueOf(7);
	public static final BigInteger Q = BigInteger.probablePrime(LAMDA, sRand); // مرتبه گروه (prime order)

	public static final BigInteger EXP_MOD = Q.subtract(BigInteger.ONE);

	// (اصلاح شده) k مخفی برای تعریف h
	public static final BigInteger k = BigInteger.probablePrime(LAMDA, sRand); // k مخفی
	public static final BigInteger h = g.modPow(k, Q); // h = g^k

	// (اصلاح شده) d = 3 (اطمینان از وجود معکوس پیمانه‌ای)
	public static final BigInteger d = BigInteger.valueOf(3);
	public static final BigInteger d_inv = d.modInverse(EXP_MOD); // d^-1 mod Q

	// برای رمزنگاری متقارن
	private static final String AES_MODE = "AES/CBC/PKCS5Padding";

	// --- توابع ریاضی و گروهی ---

	public static BigInteger power(BigInteger base, BigInteger exponent) {
		BigInteger expReduced = exponent.mod(EXP_MOD); // reduce exponent modulo Q-1
		return base.modPow(expReduced, Q);
	}

	public static BigInteger KA_agree(BigInteger sk, BigInteger pk) {
		return power(pk, sk);
	}

	public static BigInteger HF(BigInteger x, BigInteger delta, BigInteger rho) {
		return delta.multiply(x).add(rho).mod(Q);
	}

	// PRG (تغییر یافته برای تولید بردار)
	public static List<BigInteger> PRG(BigInteger seed, int size) {
		List<BigInteger> vector = new ArrayList<>(size);
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			for (int i = 0; i < size; i++) {
				byte[] seedBytes = seed.add(BigInteger.valueOf(i)).toByteArray();
				byte[] hash = digest.digest(seedBytes);
				vector.add(new BigInteger(1, Arrays.copyOfRange(hash, 0, 16)).mod(Q));
			}
			return vector;
		} catch (Exception e) {
			throw new RuntimeException("PRG failed", e);
		}
	}

	// (توابع AE.enc/dec بدون تغییر باقی می‌مانند)
	private static SecretKeySpec getAesKey(BigInteger KA_Key) {
		try {
			MessageDigest sha = MessageDigest.getInstance("SHA-256");
			byte[] key = sha.digest(KA_Key.toByteArray());
			return new SecretKeySpec(Arrays.copyOf(key, LAMDA), "AES");
		} catch (Exception e) {
			throw new RuntimeException("Key generation failed", e);
		}
	}

	public static String AE_enc(BigInteger KA_Key, String message) {
		try {
			SecretKeySpec secretKey = getAesKey(KA_Key);
			Cipher cipher = Cipher.getInstance(AES_MODE);
			SecureRandom random = new SecureRandom();
			byte[] iv = new byte[cipher.getBlockSize()];
			random.nextBytes(iv);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
			byte[] encryptedData = cipher.doFinal(message.getBytes("UTF-8"));
			String ivBase64 = Base64.getEncoder().encodeToString(iv);
			String dataBase64 = Base64.getEncoder().encodeToString(encryptedData);
			return ivBase64 + ":" + dataBase64;
		} catch (Exception e) {
			throw new RuntimeException("Encryption failed", e);
		}
	}

	public static String AE_dec(BigInteger KA_Key, String encrypted) {
		try {
			String[] parts = encrypted.split(":");
			if (parts.length != 2)
				throw new IllegalArgumentException("Invalid encrypted format");
			byte[] iv = Base64.getDecoder().decode(parts[0]);
			byte[] encryptedData = Base64.getDecoder().decode(parts[1]);
			SecretKeySpec secretKey = getAesKey(KA_Key);
			Cipher cipher = Cipher.getInstance(AES_MODE);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
			byte[] decryptedData = cipher.doFinal(encryptedData);
			return new String(decryptedData, "UTF-8");
		} catch (Exception e) {
			return null; // بازگشت null در صورت خطای رمزگشایی
		}
	}

	// --- توابع اشتراک راز شامیر (S.share/S.recon) ---

	// (اصلاح شده)
	public static class ShamirPoint {
		public final BigInteger x;
		public final BigInteger y;

		ShamirPoint(BigInteger x, BigInteger y) {
			this.x = x;
			this.y = y;
		}

		@Override
		public String toString() {
			return x + "|" + y;
		}

		public static ShamirPoint fromString(String s) {
			String[] parts = s.split("\\|");
			if (parts.length != 2)
				return null;
			return new ShamirPoint(new BigInteger(parts[0]), new BigInteger(parts[1]));
		}
	}

	public static List<ShamirPoint> S_share(BigInteger secret, int t, List<Integer> uIndices) {
		int degree = t - 1;
		List<BigInteger> coeffs = new ArrayList<>();
		coeffs.add(secret); // a_0 = راز
		SecureRandom random = new SecureRandom();
		for (int i = 1; i <= degree; i++) {
			coeffs.add(new BigInteger(Q.bitLength(), random).mod(Q.subtract(BigInteger.ONE)).add(BigInteger.ONE));
		}

		List<ShamirPoint> shares = new ArrayList<>();
		for (Integer index : uIndices) {
			BigInteger x = BigInteger.valueOf(index);
			BigInteger y = BigInteger.ZERO;
			for (int j = 0; j <= degree; j++) {
				BigInteger term = coeffs.get(j).multiply(x.modPow(BigInteger.valueOf(j), Q)).mod(Q);
				y = y.add(term).mod(Q);
			}
			shares.add(new ShamirPoint(x, y));
		}
		return shares;
	}

	public static BigInteger S_recon(List<ShamirPoint> shares, int t) {
		if (shares.size() < t) {
			throw new IllegalArgumentException("Not enough shares (t = " + t + ", provided = " + shares.size() + ")");
		}
		List<ShamirPoint> tShares = shares.subList(0, t);
		BigInteger secret = BigInteger.ZERO;

		for (int i = 0; i < t; i++) {
			BigInteger xi = tShares.get(i).x;
			BigInteger yi = tShares.get(i).y;
			BigInteger numerator = BigInteger.ONE;
			BigInteger denominator = BigInteger.ONE;

			for (int j = 0; j < t; j++) {
				if (i != j) {
					BigInteger xj = tShares.get(j).x;
					numerator = numerator.multiply(xj.negate()).mod(Q);
					denominator = denominator.multiply(xi.subtract(xj)).mod(Q);
				}
			}
			BigInteger inverseDenominator = denominator.modInverse(Q);
			BigInteger lagrangeCoefficient = numerator.multiply(inverseDenominator).mod(Q);
			secret = secret.add(yi.multiply(lagrangeCoefficient)).mod(Q);
		}
		return secret;
	}
}