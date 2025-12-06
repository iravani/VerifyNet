import java.math.BigInteger;
import it.unisa.dia.gas.jpbc.Element;

public class Round3Output {
    public final BigInteger sigma; // aggregated gradient (یا اولین عنصر)
    public final Element A; // aggregated g^{hash} 
    public final Element B; // aggregated h^{hash}
    public final Element L; // aggregated g^{L_n_exponent}
    public final Element Q; // aggregated h^{L_n_exponent}
    public final BigInteger Omega; // optional flag

    public Round3Output(BigInteger sigma, Element A, Element B, Element L, Element Q, BigInteger Omega) {
        this.sigma = sigma;
        this.A = A.getImmutable();
        this.B = B.getImmutable();
        this.L = L.getImmutable();
        this.Q = Q.getImmutable();
        this.Omega = Omega;
    }
}
