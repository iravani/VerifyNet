import java.math.BigInteger;
import java.util.List;
import it.unisa.dia.gas.jpbc.Element;

public class Round3Output {
    public final List<BigInteger> sigma;
    public final Element A_agg, B_agg;
    public final BigInteger sum_x_first;  // ← اینو اضافه کن!

    public Round3Output(List<BigInteger> sigma, Element A_agg, Element B_agg, BigInteger sum_x_first) {
        this.sigma = sigma;
        this.A_agg = A_agg.getImmutable();
        this.B_agg = B_agg.getImmutable();
        this.sum_x_first = sum_x_first;  // جمع واقعی x_i[0] های همه کاربران
    }
}