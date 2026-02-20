import java.math.BigInteger;
import java.util.List;
import it.unisa.dia.gas.jpbc.Element;

public class Round2Output {
    public final List<BigInteger> maskedGradient;  // x̂
    public final Element A, B;                      // Homomorphic hash of x_n
    public final Element L, Q;                      // Proof components
    public final Element Omega;                      // Ω_n = 1
    public final Element gamma_n, nu_n;              // PF_{K1}(n) values
    public final Element E_n, F_n;                    // E_n = g^{γ_n+ν_n}, F_n = h^{γ_n+ν_n}

    public Round2Output(List<BigInteger> maskedGradient, 
                        Element A, Element B,
                        Element L, Element Q,
                        Element Omega,
                        Element gamma_n, Element nu_n,
                        Element E_n, Element F_n) {
        this.maskedGradient = maskedGradient;
        this.A = A.getImmutable();
        this.B = B.getImmutable();
        this.L = L.getImmutable();
        this.Q = Q.getImmutable();
        this.Omega = Omega.getImmutable();
        this.gamma_n = gamma_n.getImmutable();
        this.nu_n = nu_n.getImmutable();
        this.E_n = E_n.getImmutable();
        this.F_n = F_n.getImmutable();
    }
}