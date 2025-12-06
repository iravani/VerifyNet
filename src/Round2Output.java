import java.math.BigInteger;
import java.util.List;

import it.unisa.dia.gas.jpbc.Element;

public class Round2Output {
    public List<BigInteger> x_hat; // masked vector (اگر می‌خواهی همین بمونه)
    public Element A; // g^{hash}
    public Element B; // h^{hash}
    public Element L; // g^{L_n_exponent}
    public Element Q; // h^{L_n_exponent}
    public BigInteger someFlag;

    public Round2Output(List<BigInteger> x_hat, Element A, Element B, Element L, Element Q, BigInteger flag) {
        this.x_hat = x_hat;
        this.A = A;
        this.B = B;
        this.L = L;
        this.Q = Q;
        this.someFlag = flag;
    }
}