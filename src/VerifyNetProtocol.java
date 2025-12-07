import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

enum Round { R0, R1, R2, R3, R4 }

public class VerifyNetProtocol {
    private static final int NUM_EPOCHS = 1;
    private static final int GRADIENT_SIZE = 1000;
    private static final double DROPOUT_RATE = 0.1;
    private static final int USER_COUNT = 100;
    private static final int SHAMIR_TRESHOLD = 50;

    public static List<User> filterUsersByDropout(List<User> users, double rate) {
        if (rate == 0.0) return new ArrayList<>(users);
        Random rand = new Random(42);
        return users.stream()
                .filter(u -> rand.nextDouble() >= rate)
                .collect(Collectors.toList());
    }

    public static void main(String[] args) {
        SecureRandom secRand = new SecureRandom();

        System.out.println("════════════════════════════════════════════════");
        System.out.println("       VerifyNet Protocol Simulation");
        System.out.println("       Secure Aggregation with Verification");
        System.out.println("════════════════════════════════════════════════\n");

        // --- Pairing Setup ---
        int rBits = 160, qBits = 512;
        TypeACurveGenerator pg = new TypeACurveGenerator(rBits, qBits);
        PairingParameters params = pg.generate();
        Pairing pairing = PairingFactory.getPairing(params);

        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element k = pairing.getZr().newRandomElement().getImmutable();
        Element h = g.powZn(k).getImmutable();

        Crypto.initPairing(pairing, g, h);

        System.out.printf("Pairing:  : Type A (%d-bit r, %d-bit q)\n", rBits, qBits);
        System.out.printf("Generator g: %s...\n", g.toString().substring(0, 40));
        System.out.printf("Public h   : %s...\n\n", h.toString().substring(0, 40));

        // --- Key Generation ---
        List<User> allUsers = new ArrayList<>();
        for (int i = 1; i <= USER_COUNT; i++) {
            BigInteger N_sk_bigint = new BigInteger(Crypto.r.bitLength() - 1, secRand).mod(Crypto.r);
            BigInteger P_sk_bigint = new BigInteger(Crypto.r.bitLength() - 1, secRand).mod(Crypto.r);

            Element N_sk_Zr = Crypto.toZr(N_sk_bigint);
            Element P_sk_Zr = Crypto.toZr(P_sk_bigint);
            Element N_pk = Crypto.g.powZn(N_sk_Zr).getImmutable();
            Element P_pk = Crypto.g.powZn(P_sk_Zr).getImmutable();

            allUsers.add(new User(i, N_pk, N_sk_Zr, P_pk, P_sk_Zr, GRADIENT_SIZE));
        }
        System.out.printf("KeyGen     : %d users generated (N_pk, N_sk_Zr, P_pk, P_sk_Zr)\n\n", USER_COUNT);

        BigInteger delta = new BigInteger(64, secRand).mod(Crypto.Q);
        BigInteger rho  = new BigInteger(64, secRand).mod(Crypto.Q);
        BigInteger gamma_global = new BigInteger(64, secRand).mod(Crypto.r);
        BigInteger nu_global    = new BigInteger(64, secRand).mod(Crypto.r);

        // --- Epoch Loop ---
        for (int epoch = 1; epoch <= NUM_EPOCHS; epoch++) {
            ExecutionTimer.reset();
            System.out.printf("══════════════════ EPOCH %d ══════════════════\n", epoch);

            Server server = new Server();

            // ── R0: Initialization ──
            System.out.print("R0 | Initialization + Dropout ... ");
            server.round0_Initialization(allUsers, SHAMIR_TRESHOLD, DROPOUT_RATE, GRADIENT_SIZE);
            List<User> U1 = server.U1;
            System.out.printf("→ %d users survived (τ = %d)\n", U1.size(), server.tau.longValue());

            if (U1.size() < SHAMIR_TRESHOLD) {
                System.out.println("Not enough users after R0. Skipping epoch.\n");
                continue;
            }

            // ── R1: Key Sharing ──
            System.out.print("R1 | Secure Key Sharing ... ");
            List<User> U1_R1 = filterUsersByDropout(U1, DROPOUT_RATE);
            if (U1_R1.size() < SHAMIR_TRESHOLD) {
                System.out.println("Not enough users after R1 dropout.\n");
                continue;
            }
            Map<Integer, Map<Integer, String>> all_P_n_m = new HashMap<>();
            for (User u : U1_R1) {
                all_P_n_m.put(u.id, u.round1_KeySharing(U1_R1, SHAMIR_TRESHOLD));
            }
            Map<Integer, String> P_m_n_all = server.round1_KeySharing(all_P_n_m);
            System.out.printf("→ %d encrypted shares broadcasted\n", P_m_n_all.size());

            // ── R2: Masked Input Submission ──
            System.out.print("R2 | Masked Input Submission ... ");
            List<User> U2 = filterUsersByDropout(U1_R1, DROPOUT_RATE);
            if (U2.size() < SHAMIR_TRESHOLD) {
                System.out.println("Not enough users after R2 dropout.\n");
                continue;
            }
            Map<Integer, Round2Output> round2Outputs = new HashMap<>();
            for (User u : U2) {
                Round2Output out = u.round2_MaskedInput(
                    P_m_n_all, U2, server.tau, delta, rho, gamma_global, nu_global);
                round2Outputs.put(u.id, out);
            }
            System.out.printf("→ %d masked vectors + proofs received\n", U2.size());

            // ── R3: Unmasking & Aggregation ──
            System.out.print("R3 | Unmasking & Aggregation ... ");
            List<User> U3 = filterUsersByDropout(U2, DROPOUT_RATE);
            if (U3.size() < SHAMIR_TRESHOLD) {
                System.out.println("Not enough users after R3 dropout.\n");
                continue;
            }

            U3.forEach(User::updateLocalGradient);

            Map<Integer, Round3Input> round3Inputs = new HashMap<>();
            for (User u : U3) {
                round3Inputs.put(u.id, u.round3_Unmasking(P_m_n_all, U3));
            }

            Map<Integer, Round2Output> finalR2 = new HashMap<>();
            for (User u : U3) {
                if (round2Outputs.containsKey(u.id)) {
                    finalR2.put(u.id, round2Outputs.get(u.id));
                }
            }

            Round3Output result = server.round3_UnmaskingAndAggregation(finalR2, round3Inputs, U3, SHAMIR_TRESHOLD);
            System.out.printf("→ Σ = [%s, ..., ?] (only first component shown)\n", result.sigma.get(0));

            // ── R4: Verification ──
            System.out.print("R4 | Pairing-based Verification ... ");
            int passed = 0;
            BigInteger phi_server = result.phi_total;

            for (User u : U3) {
                boolean ok = u.round4_Verification_withJPBC(
                    Crypto.pairing, Crypto.g, Crypto.h,
                    result.A, result.B, result.L, result.Q,
                    phi_server
                );
                if (ok) passed++;
            }

            String verdict = (passed == U3.size()) ? "ALL PASSED" : "SOME FAILED";
            System.out.printf("→ %d / %d users verified → %s\n", passed, U3.size(), verdict);

            if (passed == U3.size()) {
                System.out.println("    SUCCESS: VerifyNet verification PASSED 100%!");
            } else {
                System.out.println("    WARNING: Verification FAILED for some users!");
            }

            System.out.println();
            ExecutionTimer.printTable(DROPOUT_RATE);
            System.out.println("════════════════════════════════════════════════\n");
        }
    }
}