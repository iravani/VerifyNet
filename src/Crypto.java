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
    // Constants
    public static final int AES_KEY_BYTES = 32;
    private static final String AES_MODE = "AES/CBC/PKCS5Padding";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    
    // Pairing parameters
    public static Pairing pairing = null;
    public static Element generator = null;        // g ∈ G1
    public static Element publicKey = null;        // h = g^k
    public static BigInteger groupOrder = null;    // order of G1
    
    // Homomorphic hash parameters (δ, ρ)
    public static BigInteger delta = null;
    public static BigInteger rho = null;
    public static HomomorphicHash homomorphicHash = null;
    
    // PRF keys (K1, K2)
    public static BigInteger K1 = null;
    public static BigInteger K2 = null;
    
    // d parameter for d-th root
    public static int d = 3;
    
    // Field modulus for Shamir sharing
    public static final BigInteger Q = BigInteger.probablePrime(254, SECURE_RANDOM);

    // ==================== INITIALIZATION ====================
    
    public static void initPairing(Pairing p, Element g, Element h) {
        pairing = p;
        generator = g.getImmutable();
        publicKey = h.getImmutable();
        groupOrder = pairing.getG1().getOrder();
    }
    
    public static void initHomomorphicHash(BigInteger deltaParam, BigInteger rhoParam) {
        delta = deltaParam;
        rho = rhoParam;
        homomorphicHash = new HomomorphicHash(delta, rho, groupOrder, generator, publicKey);
    }
    
    public static void initPRFKeys(BigInteger k1, BigInteger k2) {
        K1 = k1;
        K2 = k2;
    }

    // ==================== PRF FUNCTIONS ====================
    
    /**
     * PRF_K1 returns [γ_n, ν_n] as two Elements
     */
    public static Element[] PRF_K1(int userId) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] input = K1.toByteArray();
            byte[] userIdBytes = BigInteger.valueOf(userId).toByteArray();
            sha256.update(input);
            sha256.update(userIdBytes);
            byte[] hash = sha256.digest();
            
            BigInteger gamma_n = new BigInteger(1, Arrays.copyOfRange(hash, 0, 16)).mod(groupOrder);
            BigInteger nu_n = new BigInteger(1, Arrays.copyOfRange(hash, 16, 32)).mod(groupOrder);
            
            return new Element[]{toZr(gamma_n), toZr(nu_n)};
        } catch (Exception e) {
            throw new RuntimeException("PRF_K1 failed", e);
        }
    }
    
    /**
     * PRF_K2 returns [γ, ν] as two Elements
     */
    public static Element[] PRF_K2() {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] input = K2.toByteArray();
            byte[] hash = sha256.digest(input);
            
            BigInteger gamma = new BigInteger(1, Arrays.copyOfRange(hash, 0, 16)).mod(groupOrder);
            BigInteger nu = new BigInteger(1, Arrays.copyOfRange(hash, 16, 32)).mod(groupOrder);
            
            return new Element[]{toZr(gamma), toZr(nu)};
        } catch (Exception e) {
            throw new RuntimeException("PRF_K2 failed", e);
        }
    }

    // ==================== GROUP OPERATIONS ====================
    
    public static Element pow(Element base, BigInteger exponent) {
        Element expZr = pairing.getZr().newElement().set(exponent.mod(groupOrder));
        return base.duplicate().powZn(expZr).getImmutable();
    }

    public static Element pow(Element base, Element exponentZr) {
        return base.duplicate().powZn(exponentZr.duplicate()).getImmutable();
    }

    /**
     * Key Agreement: g^{sk1·sk2}
     */
    public static Element KA_agree(Element sk_Zr, Element pk_G1) {
        return pk_G1.duplicate().powZn(sk_Zr.duplicate()).getImmutable();
    }

    /**
     * Convert BigInteger to Zr element
     */
    public static Element toZr(BigInteger x) {
        Element e = pairing.getZr().newElement();
        e.set(x.mod(groupOrder));
        return e.getImmutable();
    }

    /**
     * Compute d-th root in G1: elem^(1/d)
     */
    public static Element dthRoot(Element elem, int d) {
        Element exp = toZr(BigInteger.valueOf(d).modInverse(groupOrder));
        return elem.powZn(exp).getImmutable();
    }

    // ==================== PSEUDO-RANDOM GENERATOR ====================
    
    /**
     * PRG: seed → vector of random BigIntegers mod Q
     */
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

    // ==================== AUTHENTICATED ENCRYPTION ====================
    
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
            SECURE_RANDOM.nextBytes(iv);
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

    // ==================== SHAMIR SECRET SHARING ====================
    
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
            coeffs.add(new BigInteger(Q.bitLength(), SECURE_RANDOM).mod(Q));
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