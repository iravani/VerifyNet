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
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class Crypto {
    public static final int LAMDA = 256;
    public static final int AES_KEY_BYTES = 32;
    private static final SecureRandom sRand = new SecureRandom();

    // --- فقط از pairing استفاده می‌کنیم ---
    public static Pairing pairing = null;
    public static Element g = null;        // g ∈ G1
    public static Element h = null;        // h = g^k
    public static BigInteger r = null;     // order of G1 (prime)

    // برای PRG و Shamir هنوز به یک عدد بزرگ mod Q نیاز داریم
    public static final BigInteger Q = BigInteger.probablePrime(254, sRand); // کمی کوچکتر از 256 بیت برای ایمنی

    public static void initPairing(Pairing p, Element gEl, Element hEl) {
        pairing = p;
        g = gEl.getImmutable();
        h = hEl.getImmutable();
        r = pairing.getG1().getOrder();  // مرتبه گروه G1
    }

    // --- توابع گروهی با JPBC ---
    public static Element pow(Element base, BigInteger exponent) {
        Element expZr = pairing.getZr().newElement().set(exponent.mod(r));
        return base.duplicate().powZn(expZr).getImmutable();
    }

    public static Element pow(Element base, Element exponentZr) {
        return base.duplicate().powZn(exponentZr.duplicate()).getImmutable();
    }

    // --- Key Agreement در G1 ---
    public static Element KA_agree(Element sk_Zr, Element pk_G1) {
        return pk_G1.duplicate().powZn(sk_Zr.duplicate()).getImmutable(); // g^(sk1 * sk2)
    }

    // تبدیل BigInteger به Zr
    public static Element toZr(BigInteger x) {
        Element e = pairing.getZr().newElement();
        e.set(x.mod(r));
        return e.getImmutable();
    }

    // --- PRG: seed → vector of BigInteger (mod Q) ---
    public static List<BigInteger> PRG(BigInteger seed, int size) {
        List<BigInteger> vector = new ArrayList<>(size);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (int i = 0; i < size; i++) {
                byte[] input = seed.add(BigInteger.valueOf(i)).toByteArray();
                byte[] hash = digest.digest(input);
                BigInteger val = new BigInteger(1, Arrays.copyOf(hash, 16)).mod(Q);
                vector.add(val);
            }
        } catch (Exception e) {
            throw new RuntimeException("PRG failed", e);
        }
        return vector;
    }

    // --- AE Encryption/Decryption ---
    private static final String AES_MODE = "AES/CBC/PKCS5Padding";

    private static SecretKeySpec getAesKey(BigInteger kaKey) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] key = sha.digest(kaKey.toByteArray());
            return new SecretKeySpec(Arrays.copyOf(key, AES_KEY_BYTES), "AES");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String AE_enc(BigInteger kaKey, String message) {
        try {
            SecretKeySpec key = getAesKey(kaKey);
            Cipher cipher = Cipher.getInstance(AES_MODE);
            byte[] iv = new byte[16];
            sRand.nextBytes(iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] encrypted = cipher.doFinal(message.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(iv) + ":" +
                   Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public static String AE_dec(BigInteger kaKey, String encrypted) {
        try {
            String[] parts = encrypted.split(":", 2);
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] data = Base64.getDecoder().decode(parts[1]);
            SecretKeySpec key = getAesKey(kaKey);
            Cipher cipher = Cipher.getInstance(AES_MODE);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            return new String(cipher.doFinal(data), "UTF-8");
        } catch (Exception e) {
            return null;
        }
    }

    // --- Shamir Secret Sharing (mod Q) ---
    public static class ShamirPoint {
        public final BigInteger x, y;
        public ShamirPoint(BigInteger x, BigInteger y) { this.x = x; this.y = y; }
        @Override public String toString() { return x + "|" + y; }
        public static ShamirPoint fromString(String s) {
            String[] p = s.split("\\|", 2);
            return p.length == 2 ? new ShamirPoint(new BigInteger(p[0]), new BigInteger(p[1])) : null;
        }
    }

    public static List<ShamirPoint> S_share(BigInteger secret, int t, List<Integer> indices) {
        int deg = t - 1;
        List<BigInteger> coeffs = new ArrayList<>();
        coeffs.add(secret);
        for (int i = 1; i <= deg; i++) {
            coeffs.add(new BigInteger(Q.bitLength(), sRand).mod(Q));
        }
        List<ShamirPoint> shares = new ArrayList<>();
        for (Integer idx : indices) {
            BigInteger x = BigInteger.valueOf(idx);
            BigInteger y = BigInteger.ZERO;
            BigInteger xpow = BigInteger.ONE;
            for (BigInteger c : coeffs) {
                y = y.add(c.multiply(xpow)).mod(Q);
                xpow = xpow.multiply(x).mod(Q);
            }
            shares.add(new ShamirPoint(x, y));
        }
        return shares;
    }

    public static BigInteger S_recon(List<ShamirPoint> shares, int t) {
        BigInteger secret = BigInteger.ZERO;
        for (int i = 0; i < t; i++) {
            BigInteger xi = shares.get(i).x;
            BigInteger yi = shares.get(i).y;
            BigInteger num = BigInteger.ONE, den = BigInteger.ONE;
            for (int j = 0; j < t; j++) {
                if (i == j) continue;
                BigInteger xj = shares.get(j).x;
                num = num.multiply(xj.negate()).mod(Q);
                den = den.multiply(xi.subtract(xj)).mod(Q);
            }
            BigInteger lambda = num.multiply(den.modInverse(Q)).mod(Q);
            secret = secret.add(yi.multiply(lambda)).mod(Q);
        }
        return secret;
    }
}