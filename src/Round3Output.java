import java.math.BigInteger;
import java.util.List;

import it.unisa.dia.gas.jpbc.Element;

public class Round3Output {
    public final List<BigInteger> sigma;
    public final Element A, B, L, Q;
    public final BigInteger phi_total;   // مجموع φ_i برای همه کاربران زنده در R3

    public Round3Output(List<BigInteger> sigma, Element A, Element B, Element L, Element Q, BigInteger phi_total) {
        this.sigma = sigma;
        this.A = A.getImmutable();
        this.B = B.getImmutable();
        this.L = L.getImmutable();
        this.Q = Q.getImmutable();
        this.phi_total = phi_total;
    }
}