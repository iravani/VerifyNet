import java.math.BigInteger;
import java.util.List;

import it.unisa.dia.gas.jpbc.Element;

public class Round2Output {
    public final List<BigInteger> x_hat;
    public final Element A, B, L, Q;
    public final BigInteger phi_i;        // جدید: φ_i = γ_n·Γ + ν_n·N

    public Round2Output(List<BigInteger> x_hat, Element A, Element B, Element L, Element Q, BigInteger phi_i) {
        this.x_hat = x_hat;
        this.A = A.getImmutable();
        this.B = B.getImmutable();
        this.L = L.getImmutable();
        this.Q = Q.getImmutable();
        this.phi_i = phi_i;  // ذخیره مقدار φ برای این کاربر
    }
}