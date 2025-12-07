import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class User {
    public final int id;
    // کلیدهای عمومی/خصوصی حالا در G1 و Zr هستند
    public final Element N_pk, N_sk_Zr;  // N_pk = g^{N_sk}, N_sk ∈ Zr
    public final Element P_pk, P_sk_Zr;  // کلید موقت برای راند 1

    public List<BigInteger> localGradient;
    public BigInteger beta_n;
    public BigInteger gamma_n, nu_n;
    private int gradientSize;

    public User(int id, Element n_pk, Element n_sk_zr, Element p_pk, Element p_sk_zr, int gradientSize) {
        this.id = id;
        this.N_pk = n_pk.getImmutable();
        this.N_sk_Zr = n_sk_zr.getImmutable();
        this.P_pk = p_pk.getImmutable();
        this.P_sk_Zr = p_sk_zr.getImmutable();
        this.gradientSize = gradientSize;
        updateLocalGradient();
    }

    public void updateLocalGradient() {
        Random rand = new Random(id); // برای تکرارپذیری
        this.localGradient = new ArrayList<>(gradientSize);
        for (int i = 0; i < gradientSize; i++) {
            this.localGradient.add(BigInteger.valueOf(id * 10 + rand.nextInt(5)).mod(Crypto.Q));
        }
    }

    // --- راند 1: اشتراک گذاری کلید ---
    public Map<Integer, String> round1_KeySharing(List<User> U1, int t) {
        long startTime = System.nanoTime();
        beta_n = new BigInteger(64, new SecureRandom()).mod(Crypto.Q);

        List<Integer> userIds = U1.stream().map(u -> u.id).collect(Collectors.toList());
        List<Crypto.ShamirPoint> beta_shares = Crypto.S_share(beta_n, t, userIds);
        List<Crypto.ShamirPoint> Nsk_shares = Crypto.S_share(new BigInteger(N_sk_Zr.toBytes()), t, userIds);

        Map<Integer, String> p_n_m = new HashMap<>();
        for (User m : U1) {
            // Key Agreement در G1
            Element sharedKeyElement = Crypto.KA_agree(this.P_sk_Zr, m.P_pk);
            BigInteger sharedKey = new BigInteger(1, sharedKeyElement.toBytes()).mod(Crypto.Q);

            int idx = userIds.indexOf(m.id);
            String message = String.format("%d|%d|%s|%s",
                    this.id, m.id,
                    Nsk_shares.get(idx).toString(),
                    beta_shares.get(idx).toString());

            p_n_m.put(m.id, Crypto.AE_enc(sharedKey, message));
        }
        ExecutionTimer.addClientTime(Round.R1, System.nanoTime() - startTime);
        return p_n_m;
    }

    // --- راند 2: ورودی ماسک‌گذاری شده (اصلاح نهایی) ---
    public Round2Output round2_MaskedInput(Map<Integer, String> P_m_n, List<User> U2, BigInteger tau,
                                           BigInteger delta, BigInteger rho,
                                           BigInteger gamma_global, BigInteger nu_global) {
        long startTime = System.nanoTime();

        List<BigInteger> x_hat = new ArrayList<>(gradientSize);
        Map<Integer, BigInteger> s_n_m_seeds = new HashMap<>();

        for (User m : U2) {
            if (m.id != this.id) {
                Element seedElement = Crypto.KA_agree(this.N_sk_Zr, m.N_pk);
                BigInteger seed = new BigInteger(1, seedElement.toBytes()).mod(Crypto.Q);
                s_n_m_seeds.put(m.id, seed);
            }
        }

        // ماسک‌گذاری (درست)
        List<BigInteger> prg_beta = Crypto.PRG(beta_n, gradientSize);
        List<BigInteger> pos = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));
        List<BigInteger> neg = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));

        for (User m : U2) {
            if (m.id == this.id) continue;
            BigInteger seed = s_n_m_seeds.get(m.id);
            List<BigInteger> prg_s = Crypto.PRG(seed, gradientSize);
            if (this.id < m.id) {
                pos = addVectors(pos, prg_s);
            } else {
                neg = addVectors(neg, prg_s);
            }
        }

        for (int i = 0; i < gradientSize; i++) {
            BigInteger masked = localGradient.get(i)
                    .add(prg_beta.get(i))
                    .add(pos.get(i))
                    .subtract(neg.get(i))
                    .mod(Crypto.Q);
            x_hat.add(masked);
        }

        // --- تعهد pairing-based (درست) ---
        Element r_i = Crypto.pairing.getZr().newRandomElement().getImmutable();
        Element s_i = Crypto.pairing.getZr().newRandomElement().getImmutable();
        Element t_i = Crypto.pairing.getZr().newRandomElement().getImmutable();

        Element x_i_Zr = Crypto.toZr(localGradient.get(0));

        Element A = Crypto.g.powZn(r_i).getImmutable();
        Element B = Crypto.h.powZn(r_i).mul(Crypto.g.powZn(x_i_Zr)).getImmutable();
        Element L = Crypto.g.powZn(s_i).getImmutable();

        this.gamma_n = new BigInteger(64, new SecureRandom()).mod(Crypto.r);
        this.nu_n = new BigInteger(64, new SecureRandom()).mod(Crypto.r);
        BigInteger phi_i = gamma_n.multiply(gamma_global).add(nu_n.multiply(nu_global)).mod(Crypto.r);
        Element phi_i_Zr = Crypto.toZr(phi_i);

        Element Q = Crypto.g.powZn(t_i).mul(Crypto.g.powZn(phi_i_Zr.duplicate().negate())).getImmutable();

        ExecutionTimer.addClientTime(Round.R2, System.nanoTime() - startTime);
        return new Round2Output(x_hat, A, B, L, Q, phi_i);
    }

    // --- راند 3: حذف ماسک ---
    public Round3Input round3_Unmasking(Map<Integer, String> P_m_n, List<User> U3) {
        long startTime = System.nanoTime();
        Map<Integer, Crypto.ShamirPoint> Nsk_shares = new HashMap<>();
        Map<Integer, Crypto.ShamirPoint> beta_shares = new HashMap<>();

        for (User m : U3) {
            int key = this.id * 1000 + m.id;
            if (P_m_n.containsKey(key)) {
                Element sharedKeyElement = Crypto.KA_agree(this.P_sk_Zr, m.P_pk);
                BigInteger sharedKey = new BigInteger(1, sharedKeyElement.toBytes()).mod(Crypto.Q);
                String decrypted = Crypto.AE_dec(sharedKey, P_m_n.get(key));
                if (decrypted != null && decrypted.split("\\|").length == 4) {
                    String[] p = decrypted.split("\\|");
                    Crypto.ShamirPoint nsk = Crypto.ShamirPoint.fromString(p[2]);
                    Crypto.ShamirPoint beta = Crypto.ShamirPoint.fromString(p[3]);
                    if (nsk != null) Nsk_shares.put(m.id, nsk);
                    if (beta != null) beta_shares.put(m.id, beta);
                }
            }
        }
        ExecutionTimer.addClientTime(Round.R3, System.nanoTime() - startTime);
        return new Round3Input(Nsk_shares, beta_shares);
    }

    // --- راند 4: Verification (درست) ---
    public boolean round4_Verification_withJPBC(Pairing pairing, Element g, Element h,
                                                Element A, Element B, Element L, Element Q,
                                                BigInteger phi_total) {
        Element left = pairing.pairing(A, h).getImmutable();

        Element phiZr = Crypto.toZr(phi_total);
        Element g_phi = g.powZn(phiZr).getImmutable();

        Element right = pairing.pairing(B, g)
                .mul(pairing.pairing(L, g_phi))
                .mul(pairing.pairing(Q, g))
                .getImmutable();

        boolean result = left.isEqual(right);
        System.out.println("User " + id + " Verification: " + result);
        return result;
    }

    private List<BigInteger> addVectors(List<BigInteger> a, List<BigInteger> b) {
        List<BigInteger> res = new ArrayList<>();
        for (int i = 0; i < a.size(); i++) {
            res.add(a.get(i).add(b.get(i)).mod(Crypto.Q));
        }
        return res;
    }
}