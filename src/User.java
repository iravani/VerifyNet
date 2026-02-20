import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;
import it.unisa.dia.gas.jpbc.Element;

public class User {
    public final int id;
    public final Element longTermPk, longTermSk;      // N_pk, N_sk
    public final Element ephemeralPk, ephemeralSk;    // P_pk, P_sk

    public List<BigInteger> localGradient;
    public BigInteger beta_n;                          // Random mask
    public Element gamma_n, nu_n;                      // PF_{K1}(n) values
    private int gradientSize;
    
    public User(int id, Element nPk, Element nSk, Element pPk, Element pSk, int size) {
        this.id = id;
        this.longTermPk = nPk.getImmutable();
        this.longTermSk = nSk.getImmutable();
        this.ephemeralPk = pPk.getImmutable();
        this.ephemeralSk = pSk.getImmutable();
        this.gradientSize = size;
        updateLocalGradient();
    }

    public void updateLocalGradient() {
        Random rand = new Random(id);
        this.localGradient = new ArrayList<>(gradientSize);
        for (int i = 0; i < gradientSize; i++) {
            this.localGradient.add(BigInteger.valueOf(id * 10 + rand.nextInt(5)).mod(Crypto.Q));
        }
    }

    // ==================== ROUND 1: KEY SHARING ====================
    
    public Map<Integer, String> round1_KeySharing(List<User> U1, int threshold) {
        long startTime = System.nanoTime();
        
        // Generate random β_n
        beta_n = new BigInteger(64, new SecureRandom()).mod(Crypto.Q);

        List<Integer> userIds = U1.stream().map(u -> u.id).collect(Collectors.toList());
        
        // Generate shares of β_n and long-term secret key
        List<Crypto.ShamirPoint> betaShares = Crypto.S_share(beta_n, threshold, userIds);
        List<Crypto.ShamirPoint> nskShares = Crypto.S_share(
            new BigInteger(longTermSk.toBytes()), threshold, userIds);

        Map<Integer, String> encryptedShares = new HashMap<>();
        for (User recipient : U1) {
            // Key Agreement for encryption
            Element sharedKeyElement = Crypto.KA_agree(this.ephemeralSk, recipient.ephemeralPk);
            BigInteger sharedKey = new BigInteger(1, sharedKeyElement.toBytes()).mod(Crypto.Q);

            int idx = userIds.indexOf(recipient.id);
            String message = String.format("%d|%d|%s|%s", 
                this.id, recipient.id, 
                nskShares.get(idx).toString(),
                betaShares.get(idx).toString());

            encryptedShares.put(recipient.id, Crypto.AE_enc(sharedKey, message));
        }
        
        ExecutionTimer.addClientTime(Round.R1, System.nanoTime() - startTime);
        return encryptedShares;
    }

    // ==================== ROUND 2: MASKED INPUT ====================
    
    public Round2Output round2_MaskedInput(
            Map<Integer, String> allEncryptedShares,
            List<User> activeUsers, 
            BigInteger tau,
            BigInteger delta,
            BigInteger rho,
            Element gammaGlobal,
            Element nuGlobal) 
    {
        long startTime = System.nanoTime();

        // ----- Step 1: Generate masks -----
        List<BigInteger> x_hat = new ArrayList<>(gradientSize);
        Map<Integer, BigInteger> pairwiseSeeds = new HashMap<>();

        // Generate pairwise seeds from long-term keys
        for (User other : activeUsers) {
            if (other.id != this.id) {
                Element seedElement = Crypto.KA_agree(this.longTermSk, other.longTermPk);
                BigInteger seed = new BigInteger(1, seedElement.toBytes()).mod(Crypto.Q);
                pairwiseSeeds.put(other.id, seed);
            }
        }

        // Generate PRG from β_n
        List<BigInteger> prgBeta = Crypto.PRG(beta_n, gradientSize);
        
        // Generate PRG from pairwise seeds
        List<BigInteger> posMasks = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));
        List<BigInteger> negMasks = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));

        for (User other : activeUsers) {
            if (other.id == this.id) continue;
            BigInteger seed = pairwiseSeeds.get(other.id);
            List<BigInteger> prg = Crypto.PRG(seed, gradientSize);
            if (this.id < other.id) {
                posMasks = addVectors(posMasks, prg);
            } else {
                negMasks = addVectors(negMasks, prg);
            }
        }

        // Apply masking: x̂ = x + PRG(β) + Σ_{j>i} PRG(s) - Σ_{j<i} PRG(s)
        for (int i = 0; i < gradientSize; i++) {
            BigInteger masked = localGradient.get(i)
                    .add(prgBeta.get(i))
                    .add(posMasks.get(i))
                    .subtract(negMasks.get(i))
                    .mod(Crypto.Q);
            x_hat.add(masked);
        }

        // ----- Step 2: Compute proof components using homomorphic hash -----
        
        // Get PF_{K1}(n) = (γ_n, ν_n)
        Element[] pf_k1 = Crypto.PRF_K1(this.id);
        this.gamma_n = pf_k1[0];
        this.nu_n = pf_k1[1];
        
        // Calculate sum of gradients (for homomorphic hash)
        BigInteger sum_x = BigInteger.ZERO;
        for (BigInteger x : localGradient) {
            sum_x = sum_x.add(x).mod(Crypto.groupOrder);
        }
        
        // EXACT HASH FROM THE PICTURE: HF(x_n) = (A_n, B_n)
        HomomorphicHash.HashOutput hashOutput = Crypto.homomorphicHash.hashFull(sum_x);
        Element A_n = hashOutput.A_n;
        Element B_n = hashOutput.B_n;
        
        // Calculate E_n = g^{γ_n+ν_n}
        Element gammaPlusNu = this.gamma_n.duplicate().add(this.nu_n).getImmutable();
        Element E_n = Crypto.generator.powZn(gammaPlusNu).getImmutable();
        
        // Calculate F_n = h^{γ_n+ν_n}
        Element F_n = Crypto.publicKey.powZn(gammaPlusNu).getImmutable();
        
        // Calculate L_n = (E_n · A_n^{-1})^{1/d}
        Element A_n_inv = A_n.duplicate().invert().getImmutable();
        Element E_times_A_inv = E_n.duplicate().mul(A_n_inv).getImmutable();
        Element L_n = Crypto.dthRoot(E_times_A_inv, Crypto.d);
        
        // Calculate Q_n = (F_n · B_n^{-1})^{1/d}
        Element B_n_inv = B_n.duplicate().invert().getImmutable();
        Element F_times_B_inv = F_n.duplicate().mul(B_n_inv).getImmutable();
        Element Q_n = Crypto.dthRoot(F_times_B_inv, Crypto.d);
        
        // Ω_n = 1 (identity element)
        Element Omega_n = Crypto.generator.powZn(Crypto.toZr(BigInteger.ZERO)).getImmutable();

        ExecutionTimer.addClientTime(Round.R2, System.nanoTime() - startTime);
        
        return new Round2Output(
            x_hat, A_n, B_n, L_n, Q_n, Omega_n,
            this.gamma_n, this.nu_n, E_n, F_n
        );
    }

    // ==================== ROUND 3: UNMASKING ====================
    
    public Round3Input round3_Unmasking(Map<Integer, String> allEncryptedShares, List<User> U3) {
        long startTime = System.nanoTime();
        
        Map<Integer, Crypto.ShamirPoint> nskShares = new HashMap<>();
        Map<Integer, Crypto.ShamirPoint> betaShares = new HashMap<>();

        for (User sender : U3) {
            String encrypted = allEncryptedShares.get(sender.id * 1000 + this.id);
            if (encrypted != null) {
                Element sharedKeyElement = Crypto.KA_agree(this.ephemeralSk, sender.ephemeralPk);
                BigInteger sharedKey = new BigInteger(1, sharedKeyElement.toBytes()).mod(Crypto.Q);
                
                String decrypted = Crypto.AE_dec(sharedKey, encrypted);
                if (decrypted != null) {
                    String[] parts = decrypted.split("\\|");
                    if (parts.length == 4) {
                        Crypto.ShamirPoint nsk = Crypto.ShamirPoint.fromString(parts[2]);
                        Crypto.ShamirPoint beta = Crypto.ShamirPoint.fromString(parts[3]);
                        if (nsk != null) nskShares.put(sender.id, nsk);
                        if (beta != null) betaShares.put(sender.id, beta);
                    }
                }
            }
        }
        
        ExecutionTimer.addClientTime(Round.R3, System.nanoTime() - startTime);
        return new Round3Input(nskShares, betaShares);
    }

    // ==================== ROUND 4: VERIFICATION ====================
    
    public boolean round4_Verification(
            Element A_agg, Element B_agg,
            Element L_agg, Element Q_agg,
            Element Omega_agg, Element Phi,
            BigInteger sigma_first) {
        
        long startTime = System.nanoTime();
        
        // Verification 1: (A, B) should be correctly formed (implicit)
        
        // Verification 2: e(A, h) == e(g, B)
        Element e_A_h = Crypto.pairing.pairing(A_agg, Crypto.publicKey);
        Element e_g_B = Crypto.pairing.pairing(Crypto.generator, B_agg);
        if (!e_A_h.isEqual(e_g_B)) {
            System.out.println("User " + id + ": Verification 2 failed");
            return false;
        }
        
        // Verification 3: e(L, h) == e(g, Q)
        Element e_L_h = Crypto.pairing.pairing(L_agg, Crypto.publicKey);
        Element e_g_Q = Crypto.pairing.pairing(Crypto.generator, Q_agg);
        if (!e_L_h.isEqual(e_g_Q)) {
            System.out.println("User " + id + ": Verification 3 failed");
            return false;
        }
        
        // Verification 4: Φ == e(A, h) · e(L, h)^d
        Element e_L_h_pow_d = e_L_h.powZn(Crypto.toZr(BigInteger.valueOf(Crypto.d))).getImmutable();
        Element rightSide = e_A_h.duplicate().mul(e_L_h_pow_d).getImmutable();
        if (!Phi.isEqual(rightSide)) {
            System.out.println("User " + id + ": Verification 4 failed");
            return false;
        }
        
        ExecutionTimer.addClientTime(Round.R4, System.nanoTime() - startTime);
        System.out.println("User " + id + ": All verifications PASSED");
        return true;
    }

    // ==================== HELPER METHODS ====================
    
    private List<BigInteger> addVectors(List<BigInteger> a, List<BigInteger> b) {
        List<BigInteger> result = new ArrayList<>();
        for (int i = 0; i < a.size(); i++) {
            result.add(a.get(i).add(b.get(i)).mod(Crypto.Q));
        }
        return result;
    }
}