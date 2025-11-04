import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;
import java.security.SecureRandom;

public class VNetSimulator {
    // =========================================================================
    // --- 1. CONFIGURATION PARAMETERS AND GLOBAL VARIABLES ---
    // =========================================================================
	public static SecureRandom sRand = new SecureRandom();
	
	public static final int LAMDA = 128;
	public static final BigInteger g = BigInteger.probablePrime(LAMDA, sRand); // Generator of G1
	public static final BigInteger h = BigInteger.probablePrime(LAMDA, sRand); // Generator of G2
	
    public static final int USERS_SIZE = 200; // n: Total number of users
    public static final int GRAD_SIZE = 1000; // L: Gradient vector size
    public static final int SEC_PARAM_BITS = 1024; // Security Parameter (for key lengths)
    public static final BigInteger PRIME_MODULUS = new BigInteger("292021034479533383832962458428178129841"); // A large
                                                                                                              // hypothetical
                                                                                                              // modulus
    public static final int SHAMIR_THRESHOLD = 50; // T: Shamir's threshold
    public static final double DROPOUT_RATE = 0.1; // Dropout rate (α)
    public static final int ITERATIONS = 10; // Number of simulation runs

    public static DscVNet vnetInstance;
    public static DscTimeMeasure globalTimemeasure = new DscTimeMeasure();
    public static TimeMeasured timeMeasured = new TimeMeasured();

    // =========================================================================
    // --- 2. CORE DATA STRUCTURES ---
    // =========================================================================

    // (A) Basic Cryptographic Structures: Pair, Share, Cipher, ElementGT
    public static class Pair {
        // Mocking a G1 point (x, y)
        public BigInteger A; // x-coordinate
        public BigInteger B; // y-coordinate

        public Pair(BigInteger a, BigInteger b) {
            this.A = a;
            this.B = b;
        }
    }

    public static class Share {
        // Mocking a Shamir share (x, y)
        public BigInteger[] val = new BigInteger[2];

        public Share() {
            val[0] = BigInteger.ZERO;
            val[1] = BigInteger.ZERO;
        }
    }

    public static class Cipher {
        // Mocking a ciphertext (c1, c2)
        public BigInteger c1;
        public BigInteger c2;

        public Cipher(BigInteger c1, BigInteger c2) {
            this.c1 = c1;
            this.c2 = c2;
        }
    }

    public static class ElementGT {
        // Mocking an element in the GT group
        public BigInteger value;

        public ElementGT(BigInteger val) {
            this.value = val;
        }
    }

    public static class DscThss {
        // Threshold Secret Sharing Structure
        public BigInteger[] sharesX;
        public BigInteger[] sharesY;
        public BigInteger recoveredSecret;
        public int degree;
        public int threshold;

        public DscThss(int maxUsers) {
            sharesX = new BigInteger[maxUsers];
            sharesY = new BigInteger[maxUsers];
            recoveredSecret = BigInteger.ZERO;
        }
    }

    // (B) User Structure (depends on Share)
    public static class DscUser {
        public BigInteger pSk, pPk, nSk, nPk; // p/n keys
        public BigInteger[] localVector = new BigInteger[GRAD_SIZE]; // Local gradient vector (g_i)
        public BigInteger[] maskedLocalVector = new BigInteger[GRAD_SIZE]; // Masked vector

        public Share[][] nskNm = new Share[USERS_SIZE][USERS_SIZE]; // nsk_i shares for j
        public Share[][] betaNm = new Share[USERS_SIZE][USERS_SIZE]; // beta_i shares for j
        public Share[] sData = new Share[USERS_SIZE]; // S_ij share for mutual mask

        public DscUser() {
            for (int i = 0; i < USERS_SIZE; i++) {
                sData[i] = new Share();
                for (int j = 0; j < USERS_SIZE; j++) {
                    nskNm[i][j] = new Share();
                    betaNm[i][j] = new Share();
                }
            }
            // Randomly initialize gradients for simulation
            Random rnd = new Random();
            for (int i = 0; i < GRAD_SIZE; i++) {
                // Small random values
                localVector[i] = BigInteger.valueOf(rnd.nextInt(1000));
            }
        }
    }

    // (C) Main VNet Structure (depends on DscUser, Share, DscThss, Cipher, Pair)
    public static class DscVNet {
        public DscUser[] users = new DscUser[USERS_SIZE];
        public DscThss thss = new DscThss(USERS_SIZE);
        public BigInteger[] gradGlobalVector; // Final aggregated vector

        public BigInteger d, tau; // d and tau (for Verification)
        public Share[] k = new Share[2]; // K[0], K[1]

        public boolean[] uAct1 = new boolean[USERS_SIZE]; // U1 (active initially)
        public boolean[] uAct2 = new boolean[USERS_SIZE]; // U2 (active after KeyShare)
        public boolean[] uAct3 = new boolean[USERS_SIZE]; // U3 (active after Mask)
        public boolean[] uAct4 = new boolean[USERS_SIZE]; // U4 (active after UnMask/Vrfy)

        public Cipher[][] encCiphers = new Cipher[USERS_SIZE][USERS_SIZE]; // C_i,j
        public Pair[][] ab = new Pair[USERS_SIZE][GRAD_SIZE];
        public Pair[][] lq = new Pair[USERS_SIZE][GRAD_SIZE];
        public Pair[] abProduct = new Pair[GRAD_SIZE];
        public Pair[] lqProduct = new Pair[GRAD_SIZE];
        public BigInteger[] omega = new BigInteger[USERS_SIZE]; // ω_i
        public BigInteger omegaProduct;

        public DscVNet() {
            for (int i = 0; i < USERS_SIZE; i++)
                users[i] = new DscUser();
            k[0] = new Share();
            k[1] = new Share();
            omegaProduct = BigInteger.ONE;
        }
    }

    // (D) Timing Structures
    public static class TimeSpec {
        public long nanoseconds;

        public TimeSpec() {
            this(0);
        }

        public TimeSpec(long nano) {
            this.nanoseconds = nano;
        }
    }

    public static class DscTimeMeasure {
        public TimeSpec start = new TimeSpec();
        public TimeSpec end = new TimeSpec();
        public long milliseconds;
    }

    public static class TimeMeasured {
        public double keyshareClient = 0;
        public double keyshareServer = 0;
        public TimePair maskClient = new TimePair();
        public double maskServer = 0;
        public double unmaskClient = 0;
        public TimePair unmaskServer = new TimePair();
        public double verificationClient = 0;
        public double verificationServer = 0;

        public static class TimePair {
            public double usual = 0;
            public double overhead = 0;
        }
    }

    // =========================================================================
    // --- 3. HELPER FUNCTIONS AND MOCKED CRYPTOGRAPHIC PRIMITIVES ---
    // =========================================================================

    // A. Timing Helper
    public static void Time_Measure(DscTimeMeasure tm) {
        tm.milliseconds = (tm.end.nanoseconds - tm.start.nanoseconds) / 1_000_000;
    }

    // B. PRG Mock (using seeded Random)
    // Note: We use a random number with a seed instead of a real hash function for
    // simulation.
    public static BigInteger PRG(BigInteger seed) {
        Random rng = new Random(seed.longValue());
        // PRG output is a large random number
        return new BigInteger(SEC_PARAM_BITS, rng);
    }

    // C. PBC Operations Mock

    // Mocking Group Multiplication (G1/G2)
    public static void Pair_Mul(Pair result, Pair op1, Pair op2) {
        // Mock: Simple modular multiplication (In reality: Point addition on an
        // elliptic curve)
        result.A = op1.A.multiply(op2.A).mod(PRIME_MODULUS);
        result.B = op1.B.multiply(op2.B).mod(PRIME_MODULUS);
    }

    // Mocking Pairing (e(A, B) -> GT)
    public static ElementGT pairingApply(Pair A, Pair B) {
        // Mock: Output a random element in the GT group
        // In reality: Compute the pairing
        return new ElementGT(BigInteger.valueOf(1234567).add(A.A.add(B.A)).mod(PRIME_MODULUS));
    }

    // Mocking Homomorphic Hash and ABp preparation
    public static BigInteger[] Homomorphic_Hash(Pair[] abp, BigInteger[] grad, BigInteger deltaP0) {
        // Mock: This function should initialize ABp and return the necessary exponents.
        BigInteger[] exponents = new BigInteger[GRAD_SIZE];
        Random rnd = new Random();
        for (int i = 0; i < GRAD_SIZE; i++) {
            abp[i] = new Pair(BigInteger.valueOf(rnd.nextInt(100)), BigInteger.valueOf(rnd.nextInt(100)));
            exponents[i] = BigInteger.valueOf(i); // Exponents needed for Verification
        }
        return exponents;
    }

    // D. Thss Operations Mock

    // Mocking Secret Reconstruction with Thss
    public static BigInteger Thss_ReCons(DscThss thss) {
        // Mock: Secret Reconstruction (should implement Lagrange interpolation, but
        // mocked for simplicity)
        return BigInteger.valueOf(987654321);
    }

    // E. Other Cryptographic Operations Mock

    // Mocking Encrypt (ElGamal or similar)
    public static Cipher Encrypt(BigInteger message, BigInteger publicKey) {
        // Mock: C1 = g^r, C2 = message * publicKey^r (Simplified)
        BigInteger r = BigInteger.valueOf(new Random().nextInt(1000));
        BigInteger C1 = publicKey.modPow(r, PRIME_MODULUS);
        BigInteger C2 = message.multiply(publicKey.modPow(r, PRIME_MODULUS)).mod(PRIME_MODULUS);
        return new Cipher(C1, C2);
    }

    // Mocking Decrypt
    public static BigInteger Decrypt(Cipher cipher, BigInteger privateKey) {
        // Mock: Message = C2 * (C1^s)^-1 (Simplified)
        return cipher.c2.divide(cipher.c1.modPow(privateKey, PRIME_MODULUS)).mod(PRIME_MODULUS);
    }

    // Mocking PRF_Ki
    public static BigInteger[] PRF_Ki(Share k, BigInteger input) {
        // Mock: Output a 2-element vector from PRF
        BigInteger[] result = new BigInteger[2];
        BigInteger seed = k.val[0].add(input);
        Random rnd = new Random(seed.longValue());
        result[0] = BigInteger.valueOf(rnd.nextInt(100));
        result[1] = BigInteger.valueOf(rnd.nextInt(100));
        return result;
    }

    // Helper function for simulating dropout
    public static boolean[] randomlyZeroOut(boolean[] src, int size, double percentage) {
        boolean[] dest = Arrays.copyOf(src, size);
        int count = (int) (size * percentage);
        Random rand = new Random();
        for (int i = 0; i < count; i++) {
            int selected;
            do {
                selected = rand.nextInt(size);
            } while (selected < size && !dest[selected]);
            if (selected < size)
                dest[selected] = false;
        }
        return dest;
    }

    // Helper function to count active users
    public static int countActiveUsers(boolean[] arr) {
        int count = 0;
        for (boolean b : arr)
            if (b)
                count++;
        return count;
    }

    // =========================================================================
    // --- 4. VNET MAIN PROTOCOL STAGES ---
    // =========================================================================

    public static void VNET_Config(DscVNet vnet) {
        // Mock: Set active users based on dropout rate
        int activeUsers = (int) (USERS_SIZE * (1 - DROPOUT_RATE));

        // Mock: Initialize key parameters
        vnet.d = BigInteger.probablePrime(LAMDA, sRand); // Mock d
        vnet.tau = BigInteger.probablePrime(LAMDA, sRand); // Mock tau
        vnet.k[0].val[0] = BigInteger.probablePrime(LAMDA, sRand);
        vnet.k[1].val[0] = BigInteger.probablePrime(LAMDA, sRand);

        // Initialize active arrays (U1)
        Arrays.fill(vnet.uAct1, true);

        // Simulate initial dropout for U1
        vnet.uAct1 = randomlyZeroOut(vnet.uAct1, USERS_SIZE, DROPOUT_RATE);
    }

    public static void VNET_Init(DscVNet vnet) {
        for (int i = 0; i < USERS_SIZE; i++) {
            // Mock: Initialize p/n keys
            vnet.users[i].pSk = BigInteger.probablePrime(LAMDA, sRand);
            vnet.users[i].pPk = g.modPow(vnet.users[i].pSk, PRIME_MODULUS);

            vnet.users[i].nSk = BigInteger.probablePrime(LAMDA, sRand);
            vnet.users[i].nPk = h.modPow(vnet.users[i].nSk, PRIME_MODULUS);
        }
    }

    public static void VNET_KeyShare(DscVNet vnet) {
        long startTime = System.nanoTime(); // Start Client timing

        // Mock: Simulate KeyShare Client
        Random rnd = new Random();
        for (int i = 0; i < USERS_SIZE; i++) {
            if (!vnet.uAct1[i])
                continue;

            for (int j = 0; j < USERS_SIZE; j++) {
                if (i == j)
                    continue;

                // Mock: Generate shares for nsk_i and beta_i
                vnet.users[i].nskNm[i][j].val[0] = BigInteger.valueOf(rnd.nextInt(100)); // X
                vnet.users[i].nskNm[i][j].val[1] = BigInteger.valueOf(rnd.nextInt(100)); // Y

                vnet.users[i].betaNm[i][j].val[0] = BigInteger.valueOf(rnd.nextInt(100)); // X
                vnet.users[i].betaNm[i][j].val[1] = BigInteger.valueOf(rnd.nextInt(100)); // Y

                // Mock: Encrypt shares (Cipher_i,j)
                // Only a mocked value is encrypted here.
                BigInteger mockShareVal = vnet.users[i].nskNm[i][j].val[1];
                vnet.encCiphers[i][j] = Encrypt(mockShareVal, vnet.users[j].pPk);
            }
        }

        long endTime = System.nanoTime();
        globalTimemeasure.start.nanoseconds = startTime;
        globalTimemeasure.end.nanoseconds = endTime;
        Time_Measure(globalTimemeasure);
        timeMeasured.keyshareClient += globalTimemeasure.milliseconds;

        // ------------------------------------
        // Server Logic
        // ------------------------------------
        startTime = System.nanoTime();

        vnet.uAct2 = randomlyZeroOut(vnet.uAct1, USERS_SIZE, DROPOUT_RATE);

        for (int i = 0; i < USERS_SIZE; i++) {
            if (!vnet.uAct2[i])
                continue;
            for (int j = 0; j < USERS_SIZE; j++) {
                if (!vnet.uAct2[j] || i == j)
                    continue;

                // Mock: Server decrypts Cipher_i,j with its private key (pSk).
                if (vnet.encCiphers[i][j] != null) {
                    Decrypt(vnet.encCiphers[i][j], vnet.users[j].pSk);
                }
            }
        }

        endTime = System.nanoTime();
        globalTimemeasure.start.nanoseconds = startTime;
        globalTimemeasure.end.nanoseconds = endTime;
        Time_Measure(globalTimemeasure);
        timeMeasured.keyshareServer += globalTimemeasure.milliseconds;
    }

    public static void VNET_Mask(DscVNet vnet) {
        long startTime = System.nanoTime(); // Start Client timing

        vnet.uAct3 = randomlyZeroOut(vnet.uAct2, USERS_SIZE, DROPOUT_RATE);

        Random rnd = new Random();
        for (int i = 0; i < USERS_SIZE; i++) {
            if (!vnet.uAct3[i])
                continue;

            // 1. Generate random mask beta (β_i)
            BigInteger beta_i = BigInteger.valueOf(rnd.nextInt(10000));
            BigInteger G_beta_i = PRG(beta_i);

            // 2. Compute mutual mask (S_i,j)
            BigInteger mutualMask = BigInteger.ZERO;
            for (int j = 0; j < USERS_SIZE; j++) {
                if (!vnet.uAct3[j] || i == j)
                    continue;

                // ECDH: S_i,j = nSk_i ^ nPk_j mod P (Mock)
                BigInteger S_ij = vnet.users[j].nPk.modPow(vnet.users[i].nSk, PRIME_MODULUS);
                BigInteger G_S_ij = PRG(S_ij); // Mock: PRG for S_i,j

                if (j > i) {
                    mutualMask = mutualMask.add(G_S_ij);
                } else {
                    mutualMask = mutualMask.subtract(G_S_ij);
                }
            }

            // 3. Apply masks
            for (int k = 0; k < GRAD_SIZE; k++) {
                // Grad_Masked = localVector + G(β_i) + mutualMask
                vnet.users[i].maskedLocalVector[k] = vnet.users[i].localVector[k]
                        .add(G_beta_i).add(mutualMask).mod(PRIME_MODULUS);
            }
        }

        // 4. Generate pairs AB, LQ, and Ω
        for (int i = 0; i < USERS_SIZE; i++) {
            if (!vnet.uAct3[i])
                continue;
            for (int j = 0; j < GRAD_SIZE; j++) {
                vnet.ab[i][j] = new Pair(BigInteger.ONE, BigInteger.ONE); // Mock: A, B
                vnet.lq[i][j] = new Pair(BigInteger.ONE, BigInteger.ONE); // Mock: L, Q
            }
            vnet.omega[i] = BigInteger.valueOf(rnd.nextInt(100)).add(BigInteger.ONE);
        }

        long endTime = System.nanoTime();
        globalTimemeasure.start.nanoseconds = startTime;
        globalTimemeasure.end.nanoseconds = endTime;
        Time_Measure(globalTimemeasure);
        timeMeasured.maskClient.usual += globalTimemeasure.milliseconds;

        // ------------------------------------
        // Server Logic (Mocked)
        // ------------------------------------
        startTime = System.nanoTime();
        // The server only receives and stores the data
        endTime = System.nanoTime();
        globalTimemeasure.start.nanoseconds = startTime;
        globalTimemeasure.end.nanoseconds = endTime;
        Time_Measure(globalTimemeasure);
        timeMeasured.maskServer += globalTimemeasure.milliseconds;
    }

    public static void VNET_UNMask(DscVNet vnet) {
        long startServerTime = System.nanoTime();

        vnet.uAct4 = randomlyZeroOut(vnet.uAct3, USERS_SIZE, DROPOUT_RATE);
        int uAct4Active = countActiveUsers(vnet.uAct4);

        if (uAct4Active < SHAMIR_THRESHOLD) {
            System.out.printf("\nUnmask: not enough users to continue (%d < %d)\n", uAct4Active, SHAMIR_THRESHOLD);
            // In a real scenario, error handling would occur here.
            return;
        }

        vnet.gradGlobalVector = new BigInteger[GRAD_SIZE];
        for (int k = 0; k < GRAD_SIZE; k++) {
            vnet.gradGlobalVector[k] = BigInteger.ZERO;
        }

        // 1. Reconstruct beta and remove G(beta)
        for (int i = 0; i < USERS_SIZE; i++) {
            if (!vnet.uAct3[i])
                continue;

            int t = 0;
            for (int m = 0; t < SHAMIR_THRESHOLD && m < USERS_SIZE; m++) {
                if (vnet.uAct4[m] && (m != i)) {
                    // Collect required shares for reconstruction
                    vnet.thss.sharesX[t] = vnet.users[i].betaNm[i][m].val[0];
                    vnet.thss.sharesY[t] = vnet.users[i].betaNm[i][m].val[1];
                    t++;
                }
            }
            if (t < SHAMIR_THRESHOLD)
                continue;

            BigInteger recoveredBeta = Thss_ReCons(vnet.thss); // Mock: Reconstruct beta
            BigInteger G_beta_i = PRG(recoveredBeta); // Mock: G(beta)

            for (int j = 0; j < GRAD_SIZE; j++) {
                // Aggregate masked gradient
                vnet.gradGlobalVector[j] = vnet.gradGlobalVector[j].add(vnet.users[i].maskedLocalVector[j]);
                // Subtract G(beta_i)
                vnet.gradGlobalVector[j] = vnet.gradGlobalVector[j].subtract(G_beta_i).mod(PRIME_MODULUS);
            }
        }

        // 2. Reconstruct Nsk for dropped users (U2\U3) and remove mutual masks
        for (int i = 0; i < USERS_SIZE; i++) {
            if (!vnet.uAct2[i] || vnet.uAct3[i])
                continue; // Only dropped users

            int t = 0;
            for (int m = 0; t < SHAMIR_THRESHOLD && m < USERS_SIZE; m++) {
                if (vnet.uAct4[m] && (m != i)) {
                    vnet.thss.sharesX[t] = vnet.users[i].nskNm[i][m].val[0];
                    vnet.thss.sharesY[t] = vnet.users[i].nskNm[i][m].val[1];
                    t++;
                }
            }
            if (t < SHAMIR_THRESHOLD)
                continue;

            BigInteger recoveredNsk = Thss_ReCons(vnet.thss); // Mock: Reconstruct nSk

            for (int z = 0; z < USERS_SIZE; z++) {
                if (z == i || !vnet.uAct3[z])
                    continue; // Only active U3 users

                // ECDH: S_i,j = nPk_z ^ recovered_Nsk_i mod P (Mock)
                BigInteger S_ij = vnet.users[z].nPk.modPow(recoveredNsk, PRIME_MODULUS);
                BigInteger G_S_ij = PRG(S_ij); // Mock: G(S_ij)

                for (int j = 0; j < GRAD_SIZE; j++) {
                    if (z > i) {
                        vnet.gradGlobalVector[j] = vnet.gradGlobalVector[j].add(G_S_ij).mod(PRIME_MODULUS);
                    } else {
                        vnet.gradGlobalVector[j] = vnet.gradGlobalVector[j].subtract(G_S_ij).mod(PRIME_MODULUS);
                    }
                }
            }
        }

        long endUsualTime = System.nanoTime();
        globalTimemeasure.start.nanoseconds = startServerTime;
        globalTimemeasure.end.nanoseconds = endUsualTime;
        Time_Measure(globalTimemeasure);
        timeMeasured.unmaskServer.usual += globalTimemeasure.milliseconds;

        // 3. OverHead Computation (Verification Prep)
        long startOverheadTime = System.nanoTime();

        for (int j = 0; j < GRAD_SIZE; j++) {
            vnet.abProduct[j] = new Pair(BigInteger.ONE, BigInteger.ONE);
            vnet.lqProduct[j] = new Pair(BigInteger.ONE, BigInteger.ONE);
        }

        vnet.omegaProduct = BigInteger.ONE;
        for (int i = 0; i < USERS_SIZE; i++) {
            if (vnet.uAct3[i]) {
                for (int j = 0; j < GRAD_SIZE; j++) {
                    Pair_Mul(vnet.abProduct[j], vnet.abProduct[j], vnet.ab[i][j]);
                    Pair_Mul(vnet.lqProduct[j], vnet.lqProduct[j], vnet.lq[i][j]);
                }
                vnet.omegaProduct = vnet.omegaProduct.multiply(vnet.omega[i]).mod(PRIME_MODULUS);
            }
        }

        long endOverheadTime = System.nanoTime();
        globalTimemeasure.start.nanoseconds = startOverheadTime;
        globalTimemeasure.end.nanoseconds = endOverheadTime;
        Time_Measure(globalTimemeasure);
        timeMeasured.unmaskServer.overhead += globalTimemeasure.milliseconds;
    }

    public static void VNET_Vrfy(DscVNet vnet) {

        for (int i = 0; i < USERS_SIZE; i++) {
            if (!vnet.uAct4[i])
                continue;

            long startTime = System.nanoTime();

            // 1. Compute φ and Phi
            BigInteger[] gamma_nu = PRF_Ki(vnet.k[1], vnet.tau);
            BigInteger phi = BigInteger.ZERO;

            for (int m = 0; m < USERS_SIZE; m++) {
                if (!vnet.uAct3[m])
                    continue;

                BigInteger[] gamma_nu_n = PRF_Ki(vnet.k[0], BigInteger.valueOf(m));

                // Mock: Multiplication in the cryptographic domain (as per the paper)
                phi = phi.add(gamma_nu[0].multiply(gamma_nu_n[0]));
                phi = phi.add(gamma_nu[1].multiply(gamma_nu_n[1]));
            }
            phi = phi.mod(PRIME_MODULUS);

            // Mock: Phi = g_T^phi
            ElementGT Phi = new ElementGT(BigInteger.ONE.add(phi));

            // 2. Compute Homomorphic Hash and Phip
            Pair[] ABp = new Pair[GRAD_SIZE];

            // Mock: Convert_To_Polynomial and set degree/parameters
            BigInteger[] ABp_exponents = Homomorphic_Hash(ABp, vnet.gradGlobalVector, vnet.d);

            for (int j = 0; j < GRAD_SIZE; j++) {
                // Mock: e(A,h) and e(g,B)
                ElementGT eAh = pairingApply(vnet.abProduct[j], new Pair(BigInteger.ONE, BigInteger.ONE));
                ElementGT egB = pairingApply(new Pair(BigInteger.ONE, BigInteger.ONE), ABp[j]);

                if (!eAh.value.equals(egB.value)) {
                    // System.out.printf("[User %d] Verification failed: e(A,h) != e(g,B)\n", i);
                }

                // Mock: e(L,h) and e(g,Q)
                ElementGT eLh = pairingApply(vnet.lqProduct[j], new Pair(BigInteger.ONE, BigInteger.ONE));
                ElementGT egQ = pairingApply(new Pair(BigInteger.ONE, BigInteger.ONE), ABp[j]);

                if (!eLh.value.equals(egQ.value)) {
                    // System.out.printf("[User %d] Verification failed: e(L,h) != e(g,Q)\n", i);
                }

                // Mock: Compute Phip = e(A,h) * e(L,h)^d
                ElementGT temp = new ElementGT(eLh.value.multiply(vnet.d));
                ElementGT Phip = new ElementGT(eAh.value.add(temp.value));

                if (!Phi.value.equals(Phip.value)) {
                    // System.out.printf("[User %d] Verification failed: Phi != Phip\n", i);
                }
            }

            long endTime = System.nanoTime();
            globalTimemeasure.start.nanoseconds = startTime;
            globalTimemeasure.end.nanoseconds = endTime;
            Time_Measure(globalTimemeasure);
            timeMeasured.verificationClient += globalTimemeasure.milliseconds;
        }
    }

    // =========================================================================
    // --- 5. MAIN FUNCTION AND TIMING REPORT ---
    // =========================================================================

    public static void main(String[] args) {

        DscVNet vnet = new DscVNet();
        vnetInstance = vnet;

        System.out.printf("\n** Dropout = %.2f, n = %d, gradient size: %d, iterations: %d, threshold: %d**\n",
                DROPOUT_RATE, USERS_SIZE, GRAD_SIZE, ITERATIONS, SHAMIR_THRESHOLD);

        // --- Config & Init ---
        VNET_Config(vnet);
        VNET_Init(vnet);

        // --- Loop ---
        for (int iter = 0; iter < ITERATIONS; iter++) {

            System.out.printf("\r[Iteration %d/%d] Running protocol stages...", iter + 1, ITERATIONS);

            // 1. KeyShare
            VNET_KeyShare(vnet);

            // 2. Mask
            VNET_Mask(vnet);

            // 3. UnMask
            VNET_UNMask(vnet);

            // 4. Verify
            VNET_Vrfy(vnet);
        }

        // --- Final Report ---

        double avgKeyshareClient = timeMeasured.keyshareClient / ITERATIONS;
        double avgKeyshareServer = timeMeasured.keyshareServer / ITERATIONS;
        double avgMaskClient = timeMeasured.maskClient.usual / ITERATIONS;
        double avgMaskServer = timeMeasured.maskServer / ITERATIONS;
        double avgUnmaskServerUsual = timeMeasured.unmaskServer.usual / ITERATIONS;
        double avgUnmaskServerOverhead = timeMeasured.unmaskServer.overhead / ITERATIONS;
        double avgVerifyClient = timeMeasured.verificationClient / ITERATIONS;
        double avgVerifyServer = timeMeasured.verificationServer / ITERATIONS;

        double totalClient = avgKeyshareClient + avgMaskClient + avgVerifyClient;
        double totalServer = avgKeyshareServer + avgMaskServer + avgUnmaskServerUsual + avgUnmaskServerOverhead
                + avgVerifyServer;

        System.out.println("\n\n================================ Time Result In Miliseconds (Averaged Over "
                + ITERATIONS + " Iterations) ================");
        System.out.println("|             |             Client              |              Server             |");
        System.out.println("---------------------------------------------------------------------------------");
        System.out.printf("|   KeyShare    | %26.2f  | %26.2f  |\n", avgKeyshareClient, avgKeyshareServer);
        System.out.println("---------------------------------------------------------------------------------");
        System.out.printf("|    Mask       | %26.2f  | %26.2f  |\n", avgMaskClient, avgMaskServer);
        System.out.println("---------------------------------------------------------------------------------");
        System.out.printf("|    Unmask     | %26.2f  | %12.2f + %-11.2f (O) |\n", 0.0, avgUnmaskServerUsual,
                avgUnmaskServerOverhead);
        System.out.println("---------------------------------------------------------------------------------");
        System.out.printf("|    Verify     | %26.2f  | %26.2f  |\n", avgVerifyClient, avgVerifyServer);
        System.out.println("---------------------------------------------------------------------------------");
        System.out.printf("|    Total      | %26.2f  | %26.2f  |\n", totalClient, totalServer);
        System.out.println("---------------------------------------------------------------------------------");

        System.out.println(
                "\n**Note:** These timings are execution times for Mocked BigInteger operations and are used solely to simulate the logic of the C code and measure the execution time of the loops.");
    }
}