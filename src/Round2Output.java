import java.math.BigInteger;
import java.util.List;

public class Round2Output {
	public final List<BigInteger> x_hat;
	public final BigInteger A_n, B_n, L_n, Q_n, Omega_n;

	public Round2Output(List<BigInteger> x_hat, BigInteger A_n, BigInteger B_n, BigInteger L_n, BigInteger Q_n,
			BigInteger Omega_n) {
		this.x_hat = x_hat;
		this.A_n = A_n;
		this.B_n = B_n;
		this.L_n = L_n;
		this.Q_n = Q_n;
		this.Omega_n = Omega_n;
	}
}
