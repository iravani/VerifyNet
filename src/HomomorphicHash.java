import java.math.BigInteger;
import it.unisa.dia.gas.jpbc.Element;

/**
 * Homomorphic Hash Function HF_{δ,ρ}(x) from the VerifyNet paper
 * 
 * As shown in the picture:
 * HF_{δ,ρ}(x) = δ·x + ρ (mod r)
 * HF(x_n) = (A_n, B_n) = (g^{HF_{δ,ρ}(x_n)}, h^{HF_{δ,ρ}(x_n)})
 */
public class HomomorphicHash {
    
    private final BigInteger delta;
    private final BigInteger rho;
    private final BigInteger groupOrder;
    private final Element generator;
    private final Element publicKey;
    
    public HomomorphicHash(BigInteger delta, BigInteger rho, BigInteger groupOrder, 
                          Element generator, Element publicKey) {
        this.delta = delta;
        this.rho = rho;
        this.groupOrder = groupOrder;
        this.generator = generator.getImmutable();
        this.publicKey = publicKey.getImmutable();
    }
    
    /**
     * Compute the scalar hash value: HF_{δ,ρ}(x) = δ·x + ρ (mod r)
     */
    public BigInteger hashScalar(BigInteger x) {
        return delta.multiply(x).add(rho).mod(groupOrder);
    }
    
    /**
     * Compute the full hash output as shown in the picture:
     * HF(x_n) = (A_n, B_n) = (g^{HF(x)}, h^{HF(x)})
     */
    public HashOutput hashFull(BigInteger x) {
        // Step 1: Compute the scalar hash value
        BigInteger hf_x = hashScalar(x);
        Element hf_x_Zr = Crypto.toZr(hf_x);
        
        // Step 2: Compute A_n = g^{HF(x)}
        Element A_n = generator.powZn(hf_x_Zr).getImmutable();
        
        // Step 3: Compute B_n = h^{HF(x)}
        Element B_n = publicKey.powZn(hf_x_Zr).getImmutable();
        
        // Return the pair (A_n, B_n) exactly as in the picture
        return new HashOutput(A_n, B_n);
    }
    
    /**
     * Hash output pair (A_n, B_n) as shown in the picture
     */
    public static class HashOutput {
        public final Element A_n;
        public final Element B_n;
        
        public HashOutput(Element A_n, Element B_n) {
            this.A_n = A_n.getImmutable();
            this.B_n = B_n.getImmutable();
        }
    }
}