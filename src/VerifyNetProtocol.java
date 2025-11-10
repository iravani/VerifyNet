// =====================================================================
//  توابع و ساختارهای داده پایه (اصلاح شده)
// =====================================================================

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

enum Round {
	R0, R1, R2, R3, R4
}
/**
 * کلاس ExecutionTimer برای ردیابی زمان اجرای هر فاز.
 */
class ExecutionTimer {
    // زمان‌های سرور
    private static long server_R0 = 0;
    private static long server_R1 = 0;
    private static long server_R3 = 0;

    // زمان‌های تجمیعی کلاینت
    private static long client_R1 = 0;
    private static long client_R2 = 0;
    private static long client_R3 = 0;
    private static long client_R4 = 0;

    public static void reset() {
        server_R0 = 0;
        server_R1 = 0;
        server_R3 = 0;
        client_R1 = 0;
        client_R2 = 0;
        client_R3 = 0;
        client_R4 = 0;
    }

    public static void addServerTime(Round round, long nanos) {
        if (round == Round.R0)
            server_R0 += nanos;
        if (round == Round.R1)
            server_R1 += nanos;
        if (round == Round.R3)
            server_R3 += nanos;
    }

    // تغییر یافته برای اضافه کردن همزمان (thread-safe)
    public static synchronized void addClientTime(Round round, long nanos) {
        if (round == Round.R1)
            client_R1 += nanos;
        if (round == Round.R2)
            client_R2 += nanos;
        if (round == Round.R3)
            client_R3 += nanos;
        if (round == Round.R4)
            client_R4 += nanos;
    }

    public static void printTable(double dropoutRate) {
        System.out.println("\n--- Performance Summary Table ---");
        System.out.printf("| %-6s | %-7s | %-12s | %-12s | %-12s | %-12s | %-12s |\n",
                "Entity", "Dropout", "Key Sharing", "Masked Input", "Unmasking", "Verification", "Total");
        System.out.println(
                "|--------|---------|--------------|--------------|--------------|--------------|--------------|");

        double c_r1 = client_R1 / 1_000_000.0;
        double c_r2 = client_R2 / 1_000_000.0;
        double c_r3 = client_R3 / 1_000_000.0;
        double c_r4 = client_R4 / 1_000_000.0;
        double c_total = c_r1 + c_r2 + c_r3 + c_r4;
        System.out.printf("| %-6s | %-7.0f%% | %-12.0f | %-12.0f | %-12.0f | %-12.0f | %-12.0f |\n",
                "Client", dropoutRate * 100, c_r1, c_r2, c_r3, c_r4, c_total);

        double s_r0 = server_R0 / 1_000_000.0;
        double s_r1 = server_R1 / 1_000_000.0;
        double s_r3 = server_R3 / 1_000_000.0;
        double s_total = s_r0 + s_r1 + s_r3;
        System.out.printf("| %-6s | %-7.0f%% | %-12.0f | %-12.0f | %-12.0f | %-12.0f | %-12.0f |\n",
                "Server", dropoutRate * 100, (s_r0 + s_r1), 0.0, s_r3, 0.0, s_total);
    }
}

class Crypto {	
	public static final int LAMDA = 128;
	static SecureRandom sRand = new SecureRandom();
    // پارامترهای عمومی
    public static final BigInteger g = BigInteger.valueOf(7);
    public static final BigInteger Q = BigInteger.probablePrime(LAMDA, sRand); // مرتبه گروه (prime order)

    // (اصلاح شده) k مخفی برای تعریف h
    public static final BigInteger k = BigInteger.probablePrime(LAMDA, sRand); // k مخفی
    public static final BigInteger h = g.modPow(k, Q); // h = g^k

    // (اصلاح شده) d = 3 (اطمینان از وجود معکوس پیمانه‌ای)
    public static final BigInteger d = BigInteger.valueOf(3);
    public static final BigInteger d_inv = d.modInverse(Q); // d^-1 mod Q

    // برای رمزنگاری متقارن
    private static final String AES_MODE = "AES/CBC/PKCS5Padding";

    // --- توابع ریاضی و گروهی ---

    public static BigInteger power(BigInteger base, BigInteger exponent) {
        return base.modPow(exponent, Q);
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

// =====================================================================
// کلاس User (تغییر یافته برای رفع خطاها)
// =====================================================================

class User {
    public final int id;
    public final BigInteger N_pk, N_sk, P_pk, P_sk;
    public List<BigInteger> localGradient; // x_n (برداری)
    public BigInteger beta_n;
    public BigInteger gamma_n, nu_n; // PF_K1(n)
    private int gradientSize;

    public User(int id, BigInteger n_pk, BigInteger n_sk, BigInteger p_pk, BigInteger p_sk, int gradientSize) {
        this.id = id;
        this.N_pk = n_pk;
        this.N_sk = n_sk;
        this.P_pk = p_pk;
        this.P_sk = p_sk;
        this.gradientSize = gradientSize;
        updateLocalGradient();
    }

    // متد برای به‌روزرسانی گرادیان در هر اپوک
    public void updateLocalGradient() {
        Random rand = new Random();
        this.localGradient = new ArrayList<>(gradientSize);
        for (int i = 0; i < gradientSize; i++) {
            // مقادیر گرادیان باید در مدول Q باشند
            this.localGradient.add(BigInteger.valueOf(id * 10 + rand.nextInt(5)).mod(Crypto.Q));
        }
    }

    // --- راند 1: اشتراک گذاری کلید ---
    public Map<Integer, String> round1_KeySharing(List<User> U1, int t) {
        long startTime = System.nanoTime();

        beta_n = new BigInteger(64, new SecureRandom()).mod(Crypto.Q);

        List<Integer> userIds = U1.stream().map(u -> u.id).collect(Collectors.toList());
        List<Crypto.ShamirPoint> beta_shares = Crypto.S_share(beta_n, t, userIds);
        List<Crypto.ShamirPoint> Nsk_shares = Crypto.S_share(N_sk, t, userIds);

        Map<Integer, String> p_n_m = new HashMap<>();
        for (int i = 0; i < U1.size(); i++) {
            User m = U1.get(i);
            BigInteger sharedKey = Crypto.KA_agree(this.P_sk, m.P_pk);

            // (اصلاح شده) ارسال کامل سهم (x و y)
            String message = String.format("%d|%d|%s|%s",
                    this.id, m.id, Nsk_shares.get(i).toString(), beta_shares.get(i).toString());
            p_n_m.put(m.id, Crypto.AE_enc(sharedKey, message));
        }

        ExecutionTimer.addClientTime(Round.R1, System.nanoTime() - startTime);
        return p_n_m;
    }

    // --- راند 2: ورودی ماسک‌گذاری شده ---
    public Round2Output round2_MaskedInput(Map<Integer, String> P_m_n, List<User> U2, BigInteger tau, BigInteger delta,
            BigInteger rho, BigInteger gamma_global, BigInteger nu_global) {
        long startTime = System.nanoTime();

        List<BigInteger> x_hat = new ArrayList<>(gradientSize);
        Map<Integer, BigInteger> s_n_m_seeds = new HashMap<>();
        for (User m : U2) {
            if (m.id != this.id) {
                s_n_m_seeds.put(m.id, Crypto.KA_agree(this.N_sk, m.N_pk));
            }
        }

        // --- ماسک‌گذاری برداری ---
        List<BigInteger> prg_beta_vector = Crypto.PRG(beta_n, gradientSize);
        List<BigInteger> prg_s_positive_sum = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));
        List<BigInteger> prg_s_negative_sum = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));

        for (User m : U2) {
            if (m.id == this.id)
                continue;
            BigInteger s_val = s_n_m_seeds.get(m.id);
            List<BigInteger> prg_s_vector = Crypto.PRG(s_val, gradientSize);

            if (this.id < m.id) {
                prg_s_positive_sum = addVectors(prg_s_positive_sum, prg_s_vector);
            } else {
                prg_s_negative_sum = addVectors(prg_s_negative_sum, prg_s_vector);
            }
        }

        for (int i = 0; i < gradientSize; i++) {
            BigInteger masked_x_i = localGradient.get(i)
                    .add(prg_beta_vector.get(i))
                    .add(prg_s_positive_sum.get(i))
                    .subtract(prg_s_negative_sum.get(i))
                    .mod(Crypto.Q);
            x_hat.add(masked_x_i);
        }

        // --- محاسبه اثبات‌ها (بر اساس المان اول) ---
        // (اصلاح شده) اثبات‌ها باید بر اساس گرادیان واقعی باشند
        BigInteger hash_x_simplified = Crypto.HF(localGradient.get(0), delta, rho);
        BigInteger A_n = Crypto.power(Crypto.g, hash_x_simplified);
        BigInteger B_n = Crypto.power(Crypto.h, hash_x_simplified);

        this.gamma_n = new BigInteger(64, new SecureRandom()).mod(Crypto.Q);
        this.nu_n = new BigInteger(64, new SecureRandom()).mod(Crypto.Q);

        // (اصلاح شده) رفع خطای تقسیم بر d
        BigInteger exponent = gamma_n.multiply(gamma_global).add(nu_n.multiply(nu_global)).mod(Crypto.Q);
        BigInteger L_n_exponent = exponent.subtract(hash_x_simplified).mod(Crypto.Q);

        // (اصلاح شده) استفاده از معکوس پیمانه‌ای
        L_n_exponent = L_n_exponent.multiply(Crypto.d_inv).mod(Crypto.Q);

        BigInteger L_n = Crypto.power(Crypto.g, L_n_exponent);
        BigInteger Q_n = Crypto.power(Crypto.h, L_n_exponent);

        ExecutionTimer.addClientTime(Round.R2, System.nanoTime() - startTime);
        return new Round2Output(x_hat, A_n, B_n, L_n, Q_n, BigInteger.ONE);
    }

    // --- راند 3: حذف ماسک ---
    public Round3Input round3_Unmasking(Map<Integer, String> P_m_n, List<User> U3) {
        long startTime = System.nanoTime();
        // (اصلاح شده) ذخیره نقاط شامیر
        Map<Integer, Crypto.ShamirPoint> Nsk_shares = new HashMap<>();
        Map<Integer, Crypto.ShamirPoint> beta_shares = new HashMap<>();

        for (User m : U3) {
            // کلید برای رمزگشایی پیام‌هایی که m (فرستنده) برای n (this.id - گیرنده) فرستاده
            // است
            int key = this.id * 1000 + m.id;

            if (P_m_n.containsKey(key)) {
                BigInteger sharedKey = Crypto.KA_agree(this.P_sk, m.P_pk);
                String decrypted = Crypto.AE_dec(sharedKey, P_m_n.get(key));

                if (decrypted != null) {
                    String[] parts = decrypted.split("\\|");
                    if (parts.length == 6) {
                        // id_n(m) | id_m(this) | Nsk.toString() | beta.toString()
                        Crypto.ShamirPoint nsk_point = Crypto.ShamirPoint.fromString(parts[2] + "|" + parts[3]);
                        Crypto.ShamirPoint beta_point = Crypto.ShamirPoint.fromString(parts[4] + "|" + parts[5]);

                        if (nsk_point != null && beta_point != null) {
                            Nsk_shares.put(m.id, nsk_point);
                            beta_shares.put(m.id, beta_point);
                        }
                    }
                }
            }
        }
        ExecutionTimer.addClientTime(Round.R3, System.nanoTime() - startTime);
        return new Round3Input(Nsk_shares, beta_shares);
    }

    // --- راند 4: وارسی (اصلاح شده برای رفع خطا) ---
    public boolean round4_Verification(Round3Output serverResult, BigInteger aggregated_phi) {
        long startTime = System.nanoTime();
        BigInteger A = serverResult.A;
        BigInteger B = serverResult.B;
        BigInteger L = serverResult.L;
        BigInteger Q = serverResult.Q;

        // --- شبیه‌سازی وارسی (اصلاح شده) ---

        // (اصلاح شده) 1. eq_A: A^k == B
        // e(A, h) = e(A, g^k) = e(A^k, g)
        // e(g, B)
        // A^k == B (در شبیه‌سازی ما)
        boolean eq_A = A.modPow(Crypto.k, Crypto.Q).equals(B);

        // (اصلاح شده) 2. eq_B: (L^d)^k == Q^d
        // e(g, Q^d) = e(g, (h^exp)^d) = e(g, (g^k)^exp*d) = e(g,g)^(k*exp*d)
        // e(L^d, h) = e((g^exp)^d, g^k) = e(g,g)^(exp*d*k)
        BigInteger L_d = L.modPow(Crypto.d, Crypto.Q);
        BigInteger Q_d = Q.modPow(Crypto.d, Crypto.Q);
        boolean eq_B = L_d.modPow(Crypto.k, Crypto.Q).equals(Q_d);

        // (اصلاح شده) 3. eq_C: g^phi == A * L^d
        // Phi = g^phi
        BigInteger Phi_val = Crypto.power(Crypto.g, aggregated_phi);
        // RHS = A * L^d = g^sum(HF) * g^(phi - sum(HF)) = g^phi
        BigInteger RHS_C = A.multiply(L_d).mod(Crypto.Q);
        boolean eq_C = Phi_val.equals(RHS_C);

        boolean result = eq_A && eq_B && eq_C;
        ExecutionTimer.addClientTime(Round.R4, System.nanoTime() - startTime);

        if (!result) {
            // چاپ جزئیات خطا در صورت شکست
            System.out.printf("User %d (R4): Verification: FAILED (eqA: %b, eqB: %b, eqC: %b)\n", id, eq_A, eq_B, eq_C);
        }
        return result;
    }

    // متد کمکی برای جمع بردارها
    private List<BigInteger> addVectors(List<BigInteger> v1, List<BigInteger> v2) {
        List<BigInteger> result = new ArrayList<>(v1.size());
        for (int i = 0; i < v1.size(); i++) {
            result.add(v1.get(i).add(v2.get(i)).mod(Crypto.Q));
        }
        return result;
    }
}

// =====================================================================
// کلاس Server (اصلاح شده)
// =====================================================================

class Server {
    public List<User> U1;
    public BigInteger tau;
    private int gradientSize;

    public void round0_Initialization(List<User> allUsers, int t, double dropoutRate, int gradientSize) {
        long startTime = System.nanoTime();
        this.gradientSize = gradientSize;
        List<User> participants = VerifyNetProtocol.filterUsersByDropout(allUsers, dropoutRate);

        if (participants.size() < t) {
            this.U1 = new ArrayList<>(); // لیست خالی
        } else {
            this.U1 = participants;
        }
        this.tau = BigInteger.valueOf(this.U1.stream().mapToInt(u -> u.id).sum());
        ExecutionTimer.addServerTime(Round.R0, System.nanoTime() - startTime);
    }

    // --- راند 1: اشتراک گذاری کلید ---
    public Map<Integer, String> round1_KeySharing(Map<Integer, Map<Integer, String>> all_P_n_m) {
        long startTime = System.nanoTime();
        Map<Integer, String> P_m_n_all = new HashMap<>();
        for (Map.Entry<Integer, Map<Integer, String>> entry : all_P_n_m.entrySet()) {
            for (Map.Entry<Integer, String> innerEntry : entry.getValue().entrySet()) {
                P_m_n_all.put(innerEntry.getKey() * 1000 + entry.getKey(), innerEntry.getValue());
            }
        }
        ExecutionTimer.addServerTime(Round.R1, System.nanoTime() - startTime);
        return P_m_n_all;
    }

    // --- راند 3: حذف ماسک (اصلاح شده) ---
    public Round3Output round3_UnmaskingAndAggregation(
            Map<Integer, Round2Output> round2Outputs,
            Map<Integer, Round3Input> round3Inputs,
            List<User> U3, // کاربران بازمانده نهایی
            int t) {
        long startTime = System.nanoTime();

        // --- 1. تجمیع گرادیان‌های ماسک‌گذاری شده (برداری) ---
        List<BigInteger> sum_X_hat = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));
        for (User u : U3) {
            Round2Output output = round2Outputs.get(u.id);
            if (output != null) {
                sum_X_hat = addVectors(sum_X_hat, output.x_hat);
            }
        }

        // --- 2. بازسازی رازها و محاسبه ماسک‌ها (برداری) ---
        List<BigInteger> sum_PRG_beta = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));
        List<BigInteger> sum_PRG_s_positive = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));
        List<BigInteger> sum_PRG_s_negative = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));

        Map<Integer, BigInteger> reconstructed_N_sk = new HashMap<>();

        // (اصلاح شده) منطق بازسازی
        for (User u_n : U3) { // برای هر کاربر n که باید رازش بازسازی شود

            // ب) بازسازی beta_n
            List<Crypto.ShamirPoint> betaSharesFor_n = new ArrayList<>();
            for (User u_m : U3) { // سهم‌ها را از ورودی‌های m جمع‌آوری کن
                Round3Input input_from_m = round3Inputs.get(u_m.id);
                if (input_from_m != null && input_from_m.beta_shares.containsKey(u_n.id)) {
                    betaSharesFor_n.add(input_from_m.beta_shares.get(u_n.id));
                }
            }

            if (betaSharesFor_n.size() >= t) {
                BigInteger beta_n = Crypto.S_recon(betaSharesFor_n, t);
                sum_PRG_beta = addVectors(sum_PRG_beta, Crypto.PRG(beta_n, gradientSize));
            }

            // ج) بازسازی N_n_sk
            List<Crypto.ShamirPoint> nskSharesFor_n = new ArrayList<>();
            for (User u_m : U3) {
                Round3Input input_from_m = round3Inputs.get(u_m.id);
                if (input_from_m != null && input_from_m.Nsk_shares.containsKey(u_n.id)) {
                    nskSharesFor_n.add(input_from_m.Nsk_shares.get(u_n.id));
                }
            }

            if (nskSharesFor_n.size() >= t) {
                BigInteger N_n_sk = Crypto.S_recon(nskSharesFor_n, t);
                reconstructed_N_sk.put(u_n.id, N_n_sk);
            }
        }

        // ج) محاسبه ماسک‌های مشترک s_n,m
        for (User u_n : U3) {
            for (User u_m : U3) {
                if (u_n.id >= u_m.id)
                    continue; // فقط n < m

                BigInteger N_n_sk = reconstructed_N_sk.get(u_n.id);
                BigInteger N_m_sk = reconstructed_N_sk.get(u_m.id);

                if (N_n_sk != null && N_m_sk != null) {
                    BigInteger s_n_m = Crypto.KA_agree(N_n_sk, u_m.N_pk);
                    BigInteger s_m_n = Crypto.KA_agree(N_m_sk, u_n.N_pk);

                    // s_n,m باید برابر با s_m,n باشد
                    List<BigInteger> prg_s_n_m = Crypto.PRG(s_n_m, gradientSize);
                    List<BigInteger> prg_s_m_n = Crypto.PRG(s_m_n, gradientSize);

                    sum_PRG_s_positive = addVectors(sum_PRG_s_positive, prg_s_n_m);
                    sum_PRG_s_negative = addVectors(sum_PRG_s_negative, prg_s_m_n);
                }
            }
        }

        // 3. محاسبه گرادیان تجمیع‌شده نهایی (sigma) - برداری
        List<BigInteger> sigma = new ArrayList<>(gradientSize);
        for (int i = 0; i < gradientSize; i++) {
            BigInteger mask = sum_PRG_beta.get(i)
                    .add(sum_PRG_s_positive.get(i))
                    .subtract(sum_PRG_s_negative.get(i))
                    .mod(Crypto.Q);
            sigma.add(sum_X_hat.get(i).subtract(mask).mod(Crypto.Q));
        }

        // 4. محاسبه اثبات تجمیع‌شده (A, B, L, Q)
        BigInteger A = BigInteger.ONE;
        BigInteger B = BigInteger.ONE;
        BigInteger L = BigInteger.ONE;
        BigInteger Q = BigInteger.ONE;

        for (User u : U3) {
            Round2Output output = round2Outputs.get(u.id);
            if (output != null) {
                A = A.multiply(output.A_n).mod(Crypto.Q);
                B = B.multiply(output.B_n).mod(Crypto.Q);
                L = L.multiply(output.L_n).mod(Crypto.Q);
                Q = Q.multiply(output.Q_n).mod(Crypto.Q);
            }
        }

        ExecutionTimer.addServerTime(Round.R3, System.nanoTime() - startTime);

        return new Round3Output(sigma.get(0), A, B, L, Q, BigInteger.ONE);
    }

    // متد کمکی برای جمع بردارها
    private List<BigInteger> addVectors(List<BigInteger> v1, List<BigInteger> v2) {
        List<BigInteger> result = new ArrayList<>(v1.size());
        for (int i = 0; i < v1.size(); i++) {
            result.add(v1.get(i).add(v2.get(i)).mod(Crypto.Q));
        }
        return result;
    }
}

// =====================================================================
// کلاس‌های نگهدارنده داده (اصلاح شده)
// =====================================================================

class Round2Output {
    public final List<BigInteger> x_hat;
    public final BigInteger A_n, B_n, L_n, Q_n, Omega_n;

    public Round2Output(List<BigInteger> x_hat, BigInteger A_n, BigInteger B_n, BigInteger L_n, BigInteger Q_n,
            BigInteger Omega_n) {
        this.x_hat = x_hat;
        this.A_n = A_n;
        this.B_n = B_n;
        this.L_n = L_n;
        this.Q_n = Q_n;
        this.Omega_n = Omega_n;
    }
}

class Round3Input {
    // (اصلاح شده)
    public final Map<Integer, Crypto.ShamirPoint> Nsk_shares;
    public final Map<Integer, Crypto.ShamirPoint> beta_shares;

    public Round3Input(Map<Integer, Crypto.ShamirPoint> nsk_shares, Map<Integer, Crypto.ShamirPoint> beta_shares) {
        this.Nsk_shares = nsk_shares;
        this.beta_shares = beta_shares;
    }
}

class Round3Output {
    public final BigInteger sigma, A, B, L, Q, Omega;

    public Round3Output(BigInteger sigma, BigInteger A, BigInteger B, BigInteger L, BigInteger Q, BigInteger Omega) {
        this.sigma = sigma;
        this.A = A;
        this.B = B;
        this.L = L;
        this.Q = Q;
        this.Omega = Omega;
    }
}

// =====================================================================
// کلاس اصلی (اصلاح شده)
// =====================================================================

public class VerifyNetProtocol {

    private static final int NUM_EPOCHS = 1; // تعداد اپوک‌های آموزشی
    private static final int GRADIENT_SIZE = 1000; // سایز گرادیان کاربران
    private static final double DROPOUT_RATE = 0.1; // 10% درصد Dropout
    private static final int N = 100; // تعداد کل کاربران
    private static final int t = 50; // آستانه شامیر

    // --- تابع کمکی Dropout ---
    public static List<User> filterUsersByDropout(List<User> users, double rate) {
        if (rate == 0.0)
            return new ArrayList<>(users);
        Random rand = new Random();
        return users.stream()
                .filter(u -> rand.nextDouble() >= rate)
                .collect(Collectors.toList());
    }

    public static void main(String[] args) {
        SecureRandom secRand = new SecureRandom();

        // --- مرحله TA: تولید کلیدها ---
        List<User> allUsers = new ArrayList<>();
        for (int i = 1; i <= N; i++) {
            BigInteger N_sk = new BigInteger(64, secRand).mod(Crypto.Q);
            BigInteger P_sk = new BigInteger(64, secRand).mod(Crypto.Q);
            BigInteger N_pk = Crypto.power(Crypto.g, N_sk);
            BigInteger P_pk = Crypto.power(Crypto.g, P_sk);
            allUsers.add(new User(i, N_pk, N_sk, P_pk, P_sk, GRADIENT_SIZE));
        }
        BigInteger delta = new BigInteger(64, secRand).mod(Crypto.Q);
        BigInteger rho = new BigInteger(64, secRand).mod(Crypto.Q);
        BigInteger gamma_global = new BigInteger(64, secRand).mod(Crypto.Q);
        BigInteger nu_global = new BigInteger(64, secRand).mod(Crypto.Q);

        // --- حلقه اصلی اپوک‌ها ---
        for (int epoch = 1; epoch <= NUM_EPOCHS; epoch++) {
            ExecutionTimer.reset();
            System.out.println("\n=========================================");
            System.out.printf("--- EPOCH %d / %d ---\n", epoch, NUM_EPOCHS);
            System.out.println("=========================================");

            Server server = new Server();

            // --- R0: Initialization (با Dropout) ---
            System.out.println("--- R0: Initialization ---");
            server.round0_Initialization(allUsers, t, DROPOUT_RATE, GRADIENT_SIZE);
            List<User> U1 = server.U1; // کاربران بازمانده راند 0

            if (U1.size() < t) {
                System.out.printf("Skipping epoch %d: Not enough users after R0 dropout (%d < t=%d).\n", epoch,
                        U1.size(), t);
                continue;
            }

            // --- راند 1: اشتراک گذاری کلید (با Dropout) ---
            System.out.println("\n--- R1: Key Sharing ---");
            List<User> U1_R1 = filterUsersByDropout(U1, DROPOUT_RATE);
            if (U1_R1.size() < t) {
                System.out.printf("Skipping epoch %d: Not enough users after R1 dropout (%d < t=%d).\n", epoch,
                        U1_R1.size(), t);
                continue;
            }

            Map<Integer, Map<Integer, String>> all_P_n_m = new HashMap<>();
            for (User u : U1_R1) {
                all_P_n_m.put(u.id, u.round1_KeySharing(U1_R1, t));
            }
            Map<Integer, String> P_m_n_all = server.round1_KeySharing(all_P_n_m);

            // --- راند 2: ورودی ماسک‌گذاری شده (با Dropout) ---
            System.out.println("\n--- R2: Masked Input ---");
            List<User> U2 = filterUsersByDropout(U1_R1, DROPOUT_RATE);
            if (U2.size() < t) {
                System.out.printf("Skipping epoch %d: Not enough users after R2 dropout (%d < t=%d).\n", epoch,
                        U2.size(), t);
                continue;
            }

            Map<Integer, Round2Output> round2Outputs = new HashMap<>();
            for (User u : U2) {
                Round2Output r2out = u.round2_MaskedInput(P_m_n_all, U2, server.tau, delta, rho, gamma_global,
                        nu_global);
                round2Outputs.put(u.id, r2out);
            }

            // --- راند 3: حذف ماسک (با Dropout) ---
            System.out.println("\n--- R3: Unmasking and Aggregation ---");
            List<User> U3 = filterUsersByDropout(U2, DROPOUT_RATE);
            if (U3.size() < t) {
                System.out.printf("Skipping epoch %d: Not enough users after R3 dropout (%d < t=%d).\n", epoch,
                        U3.size(), t);
                continue;
            }

            // (اصلاح شده) محاسبه Phi بر اساس U3
            BigInteger aggregated_phi_actual = BigInteger.ZERO;
            for (User u : U3) {
                // اطمینان از اینکه کاربرانی که در U3 هستند، در U2 هم بوده‌اند
                // (gamma_n و nu_n در R2 تنظیم شده‌اند)
                if (round2Outputs.containsKey(u.id)) {
                    BigInteger exponent = u.gamma_n.multiply(gamma_global).add(u.nu_n.multiply(nu_global))
                            .mod(Crypto.Q);
                    aggregated_phi_actual = aggregated_phi_actual.add(exponent).mod(Crypto.Q);
                }
            }

            // به‌روزرسانی گرادیان‌های محلی کاربران (شبیه‌سازی اپوک جدید)
            U3.forEach(User::updateLocalGradient);

            Map<Integer, Round3Input> round3Inputs = new HashMap<>();
            for (User u : U3) {
                round3Inputs.put(u.id, u.round3_Unmasking(P_m_n_all, U3));
            }

            // (اصلاح شده) اطمینان از اینکه سرور فقط از R2Outputs کاربران U3 استفاده می‌کند
            Map<Integer, Round2Output> finalRound2Outputs = new HashMap<>();
            for (User u : U3) {
                if (round2Outputs.containsKey(u.id)) {
                    finalRound2Outputs.put(u.id, round2Outputs.get(u.id));
                }
            }

            Round3Output finalResult = server.round3_UnmaskingAndAggregation(finalRound2Outputs, round3Inputs, U3, t);
            System.out.printf("Server (R3): Final Aggregated Gradient (Sigma[0]): %s\n", finalResult.sigma.toString());

            // --- راند 4: وارسی ---
            System.out.println("\n--- R4: Verification ---");
            int successCount = 0;
            for (User u : U3) {
                if (u.round4_Verification(finalResult, aggregated_phi_actual)) {
                    successCount++;
                }
            }
            System.out.printf("--- R4 Summary: %d / %d users PASSED verification.\n", successCount, U3.size());

            // --- چاپ جدول زمان‌سنجی ---
            ExecutionTimer.printTable(DROPOUT_RATE);
        }
    }
}