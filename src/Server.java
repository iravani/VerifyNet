import java.math.BigInteger;
import java.util.*;
import it.unisa.dia.gas.jpbc.Element;

public class Server {
    public List<User> U1;
    public BigInteger tau;
    private int gradientSize;

    public void round0_Initialization(List<User> allUsers, int t, double dropoutRate, int gradientSize) {
        long startTime = System.nanoTime();
        this.gradientSize = gradientSize;
        List<User> participants = VerifyNetProtocol.filterUsersByDropout(allUsers, dropoutRate);
        this.U1 = (participants.size() < t) ? new ArrayList<>() : participants;
        this.tau = BigInteger.valueOf(this.U1.stream().mapToInt(u -> u.id).sum());
        ExecutionTimer.addServerTime(Round.R0, System.nanoTime() - startTime);
    }

    public Map<Integer, String> round1_KeySharing(Map<Integer, Map<Integer, String>> all_P_n_m) {
        long startTime = System.nanoTime();
        Map<Integer, String> P_m_n_all = new HashMap<>();
        for (var entry : all_P_n_m.entrySet()) {
            for (var inner : entry.getValue().entrySet()) {
                P_m_n_all.put(inner.getKey() * 1000 + entry.getKey(), inner.getValue());
            }
        }
        ExecutionTimer.addServerTime(Round.R1, System.nanoTime() - startTime);
        return P_m_n_all;
    }

    public Round3Output round3_UnmaskingAndAggregation(
            Map<Integer, Round2Output> round2Outputs,
            Map<Integer, Round3Input> round3Inputs,
            List<User> U3, int t) {

        long startTime = System.nanoTime();

        // 1. جمع X_hat و φ_total
        List<BigInteger> sum_X_hat = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));
        BigInteger phi_total = BigInteger.ZERO;

        Element aggA = Crypto.pairing.getG1().newOneElement().getImmutable();
        Element aggB = Crypto.pairing.getG1().newOneElement().getImmutable();
        Element aggL = Crypto.pairing.getG1().newOneElement().getImmutable();
        Element aggQ = Crypto.pairing.getG1().newOneElement().getImmutable();

        for (User u : U3) {
            Round2Output out = round2Outputs.get(u.id);
            if (out != null) {
                sum_X_hat = addVectors(sum_X_hat, out.x_hat);
                phi_total = phi_total.add(out.phi_i).mod(Crypto.r);  // درست: mod r

                aggA = aggA.duplicate().mul(out.A).getImmutable();
                aggB = aggB.duplicate().mul(out.B).getImmutable();
                aggL = aggL.duplicate().mul(out.L).getImmutable();
                aggQ = aggQ.duplicate().mul(out.Q).getImmutable();
            }
        }

        // 2. بازسازی beta_n و N_sk (به صورت BigInteger)
        List<BigInteger> sum_PRG_beta = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));
        List<BigInteger> sum_PRG_s_pos = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));
        List<BigInteger> sum_PRG_s_neg = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));

        Map<Integer, BigInteger> reconstructed_N_sk = new HashMap<>();

        for (User u_n : U3) {
            // بازسازی beta_n
            List<Crypto.ShamirPoint> betaShares = new ArrayList<>();
            for (User u_m : U3) {
                Round3Input in = round3Inputs.get(u_m.id);
                if (in != null && in.beta_shares.containsKey(u_n.id)) {
                    betaShares.add(in.beta_shares.get(u_n.id));
                }
            }
            if (betaShares.size() >= t) {
                BigInteger beta_n = Crypto.S_recon(betaShares, t);
                sum_PRG_beta = addVectors(sum_PRG_beta, Crypto.PRG(beta_n, gradientSize));
            }

            // بازسازی N_sk (به صورت BigInteger از bytes)
            List<Crypto.ShamirPoint> nskShares = new ArrayList<>();
            for (User u_m : U3) {
                Round3Input in = round3Inputs.get(u_m.id);
                if (in != null && in.Nsk_shares.containsKey(u_n.id)) {
                    nskShares.add(in.Nsk_shares.get(u_n.id));
                }
            }
            if (nskShares.size() >= t) {
                BigInteger N_sk_bigint = Crypto.S_recon(nskShares, t);
                reconstructed_N_sk.put(u_n.id, N_sk_bigint);
            }
        }

        // 3. محاسبه s_n,m
        for (User u_n : U3) {
            for (User u_m : U3) {
                if (u_n.id >= u_m.id) continue;
                BigInteger sk_n = reconstructed_N_sk.get(u_n.id);
                BigInteger sk_m = reconstructed_N_sk.get(u_m.id);
                if (sk_n != null && sk_m != null) {
                    // تبدیل به Element برای KA_agree
                    Element sk_n_Zr = Crypto.toZr(sk_n);
                    Element sk_m_Zr = Crypto.toZr(sk_m);

                    Element seed_nm = Crypto.KA_agree(sk_n_Zr, u_m.N_pk);
                    Element seed_mn = Crypto.KA_agree(sk_m_Zr, u_n.N_pk);

                    BigInteger s_nm = new BigInteger(1, seed_nm.toBytes()).mod(Crypto.Q);
                    BigInteger s_mn = new BigInteger(1, seed_mn.toBytes()).mod(Crypto.Q);

                    List<BigInteger> prg_nm = Crypto.PRG(s_nm, gradientSize);
                    List<BigInteger> prg_mn = Crypto.PRG(s_mn, gradientSize);

                    sum_PRG_s_pos = addVectors(sum_PRG_s_pos, prg_nm);
                    sum_PRG_s_neg = addVectors(sum_PRG_s_neg, prg_mn);
                }
            }
        }

        // 4. محاسبه sigma
        List<BigInteger> sigma = new ArrayList<>(gradientSize);
        for (int i = 0; i < gradientSize; i++) {
            BigInteger mask = sum_PRG_beta.get(i)
                    .add(sum_PRG_s_pos.get(i))
                    .subtract(sum_PRG_s_neg.get(i))
                    .mod(Crypto.Q);
            sigma.add(sum_X_hat.get(i).subtract(mask).mod(Crypto.Q));
        }

        ExecutionTimer.addServerTime(Round.R3, System.nanoTime() - startTime);

        return new Round3Output(sigma, aggA, aggB, aggL, aggQ, phi_total);
    }

    private List<BigInteger> addVectors(List<BigInteger> a, List<BigInteger> b) {
        List<BigInteger> res = new ArrayList<>();
        for (int i = 0; i < a.size(); i++) {
            res.add(a.get(i).add(b.get(i)).mod(Crypto.Q));
        }
        return res;
    }
}