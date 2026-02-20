import java.math.BigInteger;
import java.util.List;
import it.unisa.dia.gas.jpbc.Element;

public class Round3Output {
    public final List<BigInteger> aggregatedGradient;  // Σx_n
    public final Element A_agg, B_agg;                  // Aggregated hashes
    public final Element L_agg, Q_agg;                  // Aggregated proofs
    public final Element Omega_agg;                      // Aggregated Ω
    public final Element Phi;                            // Φ = e(g,h)^φ

    public Round3Output(List<BigInteger> aggregatedGradient,
                        Element A_agg, Element B_agg,
                        Element L_agg, Element Q_agg,
                        Element Omega_agg,
                        Element Phi) {
        this.aggregatedGradient = aggregatedGradient;
        this.A_agg = A_agg.getImmutable();
        this.B_agg = B_agg.getImmutable();
        this.L_agg = L_agg.getImmutable();
        this.Q_agg = Q_agg.getImmutable();
        this.Omega_agg = Omega_agg.getImmutable();
        this.Phi = Phi.getImmutable();
    }
}