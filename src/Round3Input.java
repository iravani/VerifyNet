import java.util.Map;

public class Round3Input {
	public final Map<Integer, Crypto.ShamirPoint> Nsk_shares;
	public final Map<Integer, Crypto.ShamirPoint> beta_shares;

	public Round3Input(Map<Integer, Crypto.ShamirPoint> nsk_shares, Map<Integer, Crypto.ShamirPoint> beta_shares) {
		this.Nsk_shares = nsk_shares;
		this.beta_shares = beta_shares;
	}
}