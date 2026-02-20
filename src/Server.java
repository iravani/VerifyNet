import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;
import it.unisa.dia.gas.jpbc.Element;

public class Server {
    // User sets after each round
    public List<User> U1;        // After R0 - initial participants
    public List<User> U2;        // After R1 - sent key shares
    public List<User> U3;        // After R2 - sent masked inputs
    public List<User> U4;        // After R3 - sent unmasking data
    
    public BigInteger tau;        // Sum of user IDs
    private int gradientSize;
    
    // Homomorphic hash parameters (needed for round3)
    private BigInteger delta;
    private BigInteger rho;
    
    // Store all encrypted shares from R1
    private Map<Integer, Map<Integer, String>> allEncryptedShares = new HashMap<>();

    // ==================== ROUND 0: INITIALIZATION ====================
    
    public void round0_Initialization(List<User> allUsers, int threshold, double dropoutRate, 
                                      int size, BigInteger delta, BigInteger rho) {
        long startTime = System.nanoTime();
        this.gradientSize = size;
        this.delta = delta;
        this.rho = rho;
        
        // Filter users based on dropout rate
        List<User> participants = VerifyNetProtocol.filterUsersByDropout(allUsers, dropoutRate);
        this.U1 = (participants.size() < threshold) ? new ArrayList<>() : participants;
        
        // Calculate τ = sum of user IDs
        this.tau = BigInteger.valueOf(this.U1.stream().mapToInt(u -> u.id).sum());
        
        ExecutionTimer.addServerTime(Round.R0, System.nanoTime() - startTime);
    }

    // ==================== ROUND 1: KEY SHARING ====================
    
    public Map<Integer, String> round1_KeySharing(Map<Integer, Map<Integer, String>> allShares) {
        long startTime = System.nanoTime();
        
        // Store all encrypted shares
        this.allEncryptedShares = allShares;
        
        // Reformat for broadcast: key = receiver_id * 1000 + sender_id
        Map<Integer, String> broadcastShares = new HashMap<>();
        for (var senderEntry : allShares.entrySet()) {
            int sender = senderEntry.getKey();
            for (var receiverEntry : senderEntry.getValue().entrySet()) {
                int receiver = receiverEntry.getKey();
                broadcastShares.put(receiver * 1000 + sender, receiverEntry.getValue());
            }
        }
        
        // Determine U2 (users who sent shares in R1)
        this.U2 = new ArrayList<>(this.U1.stream()
            .filter(u -> allShares.containsKey(u.id))
            .collect(Collectors.toList()));
        
        ExecutionTimer.addServerTime(Round.R1, System.nanoTime() - startTime);
        return broadcastShares;
    }

    // ==================== ROUND 2: RECEIVE MASKED INPUTS ====================
    
    public void round2_ReceiveMaskedInputs(Map<Integer, Round2Output> round2Outputs) {
        // Determine U3 (users who sent masked inputs in R2)
        this.U3 = new ArrayList<>(this.U2.stream()
            .filter(u -> round2Outputs.containsKey(u.id))
            .collect(Collectors.toList()));
    }

    // ==================== ROUND 3: UNMASKING & AGGREGATION ====================
    
    public Round3Output round3_UnmaskingAndAggregation(
            Map<Integer, Round2Output> round2Outputs,
            Map<Integer, Round3Input> round3Inputs,
            int threshold) {

        long startTime = System.nanoTime();

        // ----- Step 1: Aggregate masked vectors and proof components -----
        List<BigInteger> sumMaskedVectors = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));
        
        Element aggA = Crypto.pairing.getG1().newOneElement().getImmutable();
        Element aggB = Crypto.pairing.getG1().newOneElement().getImmutable();
        Element aggL = Crypto.pairing.getG1().newOneElement().getImmutable();
        Element aggQ = Crypto.pairing.getG1().newOneElement().getImmutable();
        Element aggOmega = Crypto.pairing.getG1().newOneElement().getImmutable();
        
        // For φ = Σ(γ_n + ν_n)
        Element sumGammaPlusNu = Crypto.toZr(BigInteger.ZERO);

        for (User user : U3) {
            Round2Output output = round2Outputs.get(user.id);
            if (output != null) {
                // Aggregate masked vectors (addition)
                sumMaskedVectors = addVectors(sumMaskedVectors, output.maskedGradient);
                
                // Aggregate proof components (multiplication in G1)
                aggA = aggA.duplicate().mul(output.A).getImmutable();
                aggB = aggB.duplicate().mul(output.B).getImmutable();
                aggL = aggL.duplicate().mul(output.L).getImmutable();
                aggQ = aggQ.duplicate().mul(output.Q).getImmutable();
                aggOmega = aggOmega.duplicate().mul(output.Omega).getImmutable();
                
                // Sum γ_n + ν_n
                Element gammaPlusNu = output.gamma_n.duplicate().add(output.nu_n).getImmutable();
                sumGammaPlusNu = sumGammaPlusNu.duplicate().add(gammaPlusNu).getImmutable();
            }
        }

        // ----- Step 2: Determine dropout users -----
        // U2 \ U3 = users who sent shares in R1 but dropped in R2
        List<User> droppedInR2 = new ArrayList<>(U2);
        droppedInR2.removeAll(U3);

        // ----- Step 3: Reconstruct secrets from shares -----
        Map<Integer, BigInteger> reconstructedBeta = new HashMap<>();
        Map<Integer, BigInteger> reconstructedNsk = new HashMap<>();
        
        for (User user : U3) {
            // Reconstruct β_n
            List<Crypto.ShamirPoint> betaShares = new ArrayList<>();
            for (User shareHolder : U3) {
                Round3Input input = round3Inputs.get(shareHolder.id);
                if (input != null && input.betaShares.containsKey(user.id)) {
                    betaShares.add(input.betaShares.get(user.id));
                }
            }
            if (betaShares.size() >= threshold) {
                reconstructedBeta.put(user.id, Crypto.S_recon(betaShares, threshold));
            }

            // Reconstruct long-term secret key
            List<Crypto.ShamirPoint> nskShares = new ArrayList<>();
            for (User shareHolder : U3) {
                Round3Input input = round3Inputs.get(shareHolder.id);
                if (input != null && input.nskShares.containsKey(user.id)) {
                    nskShares.add(input.nskShares.get(user.id));
                }
            }
            if (nskShares.size() >= threshold) {
                reconstructedNsk.put(user.id, Crypto.S_recon(nskShares, threshold));
            }
        }

        // ----- Step 4: Calculate all PRG values -----
        
        // PRG(β_n) for all users in U3
        List<BigInteger> sumPrgBeta = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));
        for (User user : U3) {
            BigInteger beta = reconstructedBeta.get(user.id);
            if (beta != null) {
                sumPrgBeta = addVectors(sumPrgBeta, Crypto.PRG(beta, gradientSize));
            }
        }

        // PRG(s_{n,m}) for n ∈ U3, m ∈ U2\U3
        List<BigInteger> sumPrgPos = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));
        List<BigInteger> sumPrgNeg = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));

        for (User user : U3) {
            BigInteger sk = reconstructedNsk.get(user.id);
            if (sk == null) continue;
            Element skZr = Crypto.toZr(sk);
            
            for (User dropped : droppedInR2) {
                // Get public key of dropped user
                Element pkDropped = getLongTermPk(dropped.id);
                if (pkDropped == null) continue;
                
                // Calculate shared seed
                Element seedElement = Crypto.KA_agree(skZr, pkDropped);
                BigInteger seed = new BigInteger(1, seedElement.toBytes()).mod(Crypto.Q);
                
                List<BigInteger> prg = Crypto.PRG(seed, gradientSize);
                
                if (user.id < dropped.id) {
                    sumPrgPos = addVectors(sumPrgPos, prg);
                } else {
                    sumPrgNeg = addVectors(sumPrgNeg, prg);
                }
            }
        }

        // ----- Step 5: Unmask to get final aggregated gradient -----
        // σ = Σx̂ - ΣPRG(β) - Σ_{n∈U3,m∈U2\U3: n<m} PRG(s) + Σ_{n∈U3,m∈U2\U3: n>m} PRG(s)
        List<BigInteger> aggregatedGradient = new ArrayList<>(gradientSize);
        for (int i = 0; i < gradientSize; i++) {
            BigInteger unmasked = sumMaskedVectors.get(i)
                    .subtract(sumPrgBeta.get(i))
                    .subtract(sumPrgPos.get(i))
                    .add(sumPrgNeg.get(i))
                    .mod(Crypto.Q);
            aggregatedGradient.add(unmasked);
        }

        // ----- Step 6: Calculate Φ = e(g,h)^φ where φ = Σ(γ_n+ν_n) -----
        Element Phi = Crypto.pairing.pairing(Crypto.generator, Crypto.publicKey)
            .powZn(sumGammaPlusNu).getImmutable();

        ExecutionTimer.addServerTime(Round.R3, System.nanoTime() - startTime);

        // Determine U4 (users who sent data in R3)
        this.U4 = new ArrayList<>(U3.stream()
            .filter(u -> round3Inputs.containsKey(u.id))
            .collect(Collectors.toList()));

        return new Round3Output(
            aggregatedGradient, 
            aggA, aggB, aggL, aggQ, aggOmega, 
            Phi
        );
    }

    // ==================== HELPER METHODS ====================
    
    private Element getLongTermPk(int userId) {
        for (User user : U1) {
            if (user.id == userId) return user.longTermPk;
        }
        return null;
    }

    private List<BigInteger> addVectors(List<BigInteger> a, List<BigInteger> b) {
        List<BigInteger> result = new ArrayList<>();
        for (int i = 0; i < a.size(); i++) {
            result.add(a.get(i).add(b.get(i)).mod(Crypto.Q));
        }
        return result;
    }
    
    // Getters for delta and rho (if needed elsewhere)
    public BigInteger getDelta() { return delta; }
    public BigInteger getRho() { return rho; }
}