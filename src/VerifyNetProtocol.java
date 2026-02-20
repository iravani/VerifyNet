import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

enum Round { R0, R1, R2, R3, R4 }

public class VerifyNetProtocol {
    // Protocol parameters
    private static final int NUM_EPOCHS = 1;
    private static final int GRADIENT_SIZE = 1000;
    private static final double DROPOUT_RATE = 0.1;
    private static final int USER_COUNT = 100;        // Reduced for testing
    private static final int SHAMIR_THRESHOLD = 50;   // t = 5 for 10 users
    
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static void main(String[] args) {
        printHeader();

        // ----- SETUP: Pairing Initialization -----
        int rBits = 160, qBits = 512;
        TypeACurveGenerator curveGen = new TypeACurveGenerator(rBits, qBits);
        PairingParameters params = curveGen.generate();
        Pairing pairing = PairingFactory.getPairing(params);

        // Generate public parameters: g and h = g^k
        Element generator = pairing.getG1().newRandomElement().getImmutable();
        Element secret = pairing.getZr().newRandomElement().getImmutable();
        Element publicKey = generator.powZn(secret).getImmutable();

        Crypto.initPairing(pairing, generator, publicKey);

        // ----- SETUP: Global Parameters -----
        BigInteger delta = new BigInteger(64, SECURE_RANDOM).mod(Crypto.groupOrder);
        BigInteger rho = new BigInteger(64, SECURE_RANDOM).mod(Crypto.groupOrder);
        BigInteger K1 = new BigInteger(64, SECURE_RANDOM).mod(Crypto.groupOrder);
        BigInteger K2 = new BigInteger(64, SECURE_RANDOM).mod(Crypto.groupOrder);
        
        Crypto.initHomomorphicHash(delta, rho);
        Crypto.initPRFKeys(K1, K2);

        printSetupInfo(rBits, qBits, delta, rho);

        // ----- SETUP: User Key Generation -----
        List<User> allUsers = generateUsers(USER_COUNT, GRADIENT_SIZE);
        System.out.printf("KeyGen: %d users generated\n\n", USER_COUNT);

        // ----- EPOCH LOOP -----
        for (int epoch = 1; epoch <= NUM_EPOCHS; epoch++) {
            // PASS delta and rho to runEpoch
            runEpoch(epoch, allUsers, delta, rho);
        }
    }

    // ==================== EPOCH EXECUTION ====================
    
    private static void runEpoch(int epoch, List<User> allUsers, BigInteger delta, BigInteger rho) {
        ExecutionTimer.reset();
        System.out.printf("══════════════════ EPOCH %d ══════════════════\n", epoch);

        Server server = new Server();

        // ----- ROUND 0: Initialization -----
        System.out.print("R0 | Initialization + Dropout ... ");
        server.round0_Initialization(allUsers, SHAMIR_THRESHOLD, DROPOUT_RATE, GRADIENT_SIZE, delta, rho);
        List<User> U1 = server.U1;
        System.out.printf("→ %d users survived (τ = %d)\n", U1.size(), server.tau);

        if (U1.size() < SHAMIR_THRESHOLD) {
            System.out.println("Not enough users after R0. Skipping epoch.\n");
            return;
        }

        // ----- ROUND 1: Key Sharing -----
        System.out.print("R1 | Secure Key Sharing ... ");
        List<User> U1_R1 = filterUsersByDropout(U1, DROPOUT_RATE);
        if (U1_R1.size() < SHAMIR_THRESHOLD) {
            System.out.println("Not enough users after R1 dropout.\n");
            return;
        }
        
        Map<Integer, Map<Integer, String>> allShares = new HashMap<>();
        for (User user : U1_R1) {
            allShares.put(user.id, user.round1_KeySharing(U1_R1, SHAMIR_THRESHOLD));
        }
        Map<Integer, String> broadcastShares = server.round1_KeySharing(allShares);
        System.out.printf("→ %d encrypted shares broadcasted\n", broadcastShares.size());

        // ----- ROUND 2: Masked Input Submission -----
        System.out.print("R2 | Masked Input Submission + Proofs ... ");
        List<User> U2 = server.U2;
        if (U2.size() < SHAMIR_THRESHOLD) {
            System.out.println("Not enough users after R2.\n");
            return;
        }
        
        Map<Integer, Round2Output> round2Outputs = new HashMap<>();
        for (User user : U2) {
            // Get global PF_{K2} values
            Element[] pf_k2 = Crypto.PRF_K2();
            Element gammaGlobal = pf_k2[0];
            Element nuGlobal = pf_k2[1];
            
            Round2Output output = user.round2_MaskedInput(
                broadcastShares, U2, server.tau, delta, rho, gammaGlobal, nuGlobal);
            round2Outputs.put(user.id, output);
        }
        server.round2_ReceiveMaskedInputs(round2Outputs);
        System.out.printf("→ %d masked vectors + proofs received\n", U2.size());

        // ----- ROUND 3: Unmasking & Aggregation -----
        System.out.print("R3 | Unmasking & Aggregation ... ");
        List<User> U3 = server.U3;
        if (U3.size() < SHAMIR_THRESHOLD) {
            System.out.println("Not enough users after R3.\n");
            return;
        }

        Map<Integer, Round3Input> round3Inputs = new HashMap<>();
        for (User user : U3) {
            round3Inputs.put(user.id, user.round3_Unmasking(broadcastShares, U3));
        }

        Round3Output result = server.round3_UnmaskingAndAggregation(
            round2Outputs, round3Inputs, SHAMIR_THRESHOLD);
        
        System.out.printf("→ Σ = [%s, ...] (first component)\n", 
            result.aggregatedGradient.get(0));

        // ----- ROUND 4: Verification -----
        System.out.print("R4 | Full Verification ... ");
        int passed = 0;
        List<User> U4 = server.U4;

        for (User user : U4) {
            boolean ok = user.round4_Verification(
                result.A_agg, result.B_agg,
                result.L_agg, result.Q_agg,
                result.Omega_agg, result.Phi,
                result.aggregatedGradient.get(0)
            );
            if (ok) passed++;
        }
        
        String verdict = (passed == U4.size()) ? "ALL PASSED" : "SOME FAILED";
        System.out.printf("→ %d / %d users verified → %s\n", passed, U4.size(), verdict);
        
        if (passed == U4.size()) {
            System.out.println("    SUCCESS: VerifyNet verification PASSED 100%!");
        } else {
            System.out.println("    WARNING: Verification FAILED for some users!");
        }

        System.out.println();
        ExecutionTimer.printTable(DROPOUT_RATE);
        System.out.println("════════════════════════════════════════════════\n");
    }

    // ==================== HELPER METHODS ====================
    
    private static List<User> generateUsers(int count, int gradientSize) {
        List<User> users = new ArrayList<>();
        for (int i = 1; i <= count; i++) {
            BigInteger nsk = new BigInteger(Crypto.groupOrder.bitLength() - 1, SECURE_RANDOM)
                .mod(Crypto.groupOrder);
            BigInteger psk = new BigInteger(Crypto.groupOrder.bitLength() - 1, SECURE_RANDOM)
                .mod(Crypto.groupOrder);

            Element nskZr = Crypto.toZr(nsk);
            Element pskZr = Crypto.toZr(psk);
            Element npk = Crypto.generator.powZn(nskZr).getImmutable();
            Element ppk = Crypto.generator.powZn(pskZr).getImmutable();

            users.add(new User(i, npk, nskZr, ppk, pskZr, gradientSize));
        }
        return users;
    }

    public static List<User> filterUsersByDropout(List<User> users, double rate) {
        if (rate == 0.0) return new ArrayList<>(users);
        Random rand = new Random(42);  // Fixed seed for reproducibility
        return users.stream()
                .filter(u -> rand.nextDouble() >= rate) 
                .collect(Collectors.toList());
    }

    private static void printHeader() {
        System.out.println(""
            + "════════════════════════════════════════════════"
            + "\n       VerifyNet Protocol Simulation (FULL)"
            + "\n       Secure Aggregation with Complete Verification"
            + "\n════════════════════════════════════════════════\n");
    }

    private static void printSetupInfo(int rBits, int qBits, BigInteger delta, BigInteger rho) {
        System.out.printf("Pairing: Type A (%d-bit r, %d-bit q)\n", rBits, qBits);
        System.out.printf("Generator g: %s...\n", Crypto.generator.toString().substring(0, 40));
        System.out.printf("Public key h: %s...\n", Crypto.publicKey.toString().substring(0, 40));
        System.out.printf("Global params: δ=%s..., ρ=%s...\n", 
            delta.toString().substring(0, 10), rho.toString().substring(0, 10));
    }
}