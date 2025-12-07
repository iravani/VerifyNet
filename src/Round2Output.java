import java.math.BigInteger;
import java.util.List;
import it.unisa.dia.gas.jpbc.Element;

public class Round2Output {
    public final List<BigInteger> x_hat;
    public final Element A, B;  // فقط A و B

    public Round2Output(List<BigInteger> x_hat, Element A, Element B) {
        this.x_hat = x_hat;
        this.A = A.getImmutable();
        this.B = B.getImmutable();
    }
}