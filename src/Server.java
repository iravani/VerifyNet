import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Server {
	public List<User> U1;
	public BigInteger tau;
	private int gradientSize;

	public void round0_Initialization(List<User> allUsers, int t, double dropoutRate, int gradientSize) {
		long startTime = System.nanoTime();
		this.gradientSize = gradientSize;
		List<User> participants = VerifyNetProtocol.filterUsersByDropout(allUsers, dropoutRate);

		if (participants.size() < t) {
			this.U1 = new ArrayList<>(); // لیست خالی
		} else {
			this.U1 = participants;
		}
		this.tau = BigInteger.valueOf(this.U1.stream().mapToInt(u -> u.id).sum());
		ExecutionTimer.addServerTime(Round.R0, System.nanoTime() - startTime);
	}

	// --- راند 1: اشتراک گذاری کلید ---
	public Map<Integer, String> round1_KeySharing(Map<Integer, Map<Integer, String>> all_P_n_m) {
		long startTime = System.nanoTime();
		Map<Integer, String> P_m_n_all = new HashMap<>();
		for (Map.Entry<Integer, Map<Integer, String>> entry : all_P_n_m.entrySet()) {
			for (Map.Entry<Integer, String> innerEntry : entry.getValue().entrySet()) {
				P_m_n_all.put(innerEntry.getKey() * 1000 + entry.getKey(), innerEntry.getValue());
			}
		}
		ExecutionTimer.addServerTime(Round.R1, System.nanoTime() - startTime);
		return P_m_n_all;
	}

	// --- راند 3: حذف ماسک (اصلاح شده) ---
	public Round3Output round3_UnmaskingAndAggregation(Map<Integer, Round2Output> round2Outputs,
			Map<Integer, Round3Input> round3Inputs, List<User> U3, // کاربران بازمانده نهایی
			int t) {
		long startTime = System.nanoTime();

		// --- 1. تجمیع گرادیان‌های ماسک‌گذاری شده (برداری) ---
		List<BigInteger> sum_X_hat = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));
		for (User u : U3) {
			Round2Output output = round2Outputs.get(u.id);
			if (output != null) {
				sum_X_hat = addVectors(sum_X_hat, output.x_hat);
			}
		}

		// --- 2. بازسازی رازها و محاسبه ماسک‌ها (برداری) ---
		List<BigInteger> sum_PRG_beta = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));
		List<BigInteger> sum_PRG_s_positive = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));
		List<BigInteger> sum_PRG_s_negative = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));

		Map<Integer, BigInteger> reconstructed_N_sk = new HashMap<>();

		// (اصلاح شده) منطق بازسازی
		for (User u_n : U3) { // برای هر کاربر n که باید رازش بازسازی شود

			// ب) بازسازی beta_n
			List<Crypto.ShamirPoint> betaSharesFor_n = new ArrayList<>();
			for (User u_m : U3) { // سهم‌ها را از ورودی‌های m جمع‌آوری کن
				Round3Input input_from_m = round3Inputs.get(u_m.id);
				if (input_from_m != null && input_from_m.beta_shares.containsKey(u_n.id)) {
					betaSharesFor_n.add(input_from_m.beta_shares.get(u_n.id));
				}
			}

			if (betaSharesFor_n.size() >= t) {
				BigInteger beta_n = Crypto.S_recon(betaSharesFor_n, t);
				sum_PRG_beta = addVectors(sum_PRG_beta, Crypto.PRG(beta_n, gradientSize));
			}

			// ج) بازسازی N_n_sk
			List<Crypto.ShamirPoint> nskSharesFor_n = new ArrayList<>();
			for (User u_m : U3) {
				Round3Input input_from_m = round3Inputs.get(u_m.id);
				if (input_from_m != null && input_from_m.Nsk_shares.containsKey(u_n.id)) {
					nskSharesFor_n.add(input_from_m.Nsk_shares.get(u_n.id));
				}
			}

			if (nskSharesFor_n.size() >= t) {
				BigInteger N_n_sk = Crypto.S_recon(nskSharesFor_n, t);
				reconstructed_N_sk.put(u_n.id, N_n_sk);
			}
		}

		// ج) محاسبه ماسک‌های مشترک s_n,m
		for (User u_n : U3) {
			for (User u_m : U3) {
				if (u_n.id >= u_m.id)
					continue; // فقط n < m

				BigInteger N_n_sk = reconstructed_N_sk.get(u_n.id);
				BigInteger N_m_sk = reconstructed_N_sk.get(u_m.id);

				if (N_n_sk != null && N_m_sk != null) {
					BigInteger s_n_m = Crypto.KA_agree(N_n_sk, u_m.N_pk);
					BigInteger s_m_n = Crypto.KA_agree(N_m_sk, u_n.N_pk);

					// s_n,m باید برابر با s_m,n باشد
					List<BigInteger> prg_s_n_m = Crypto.PRG(s_n_m, gradientSize);
					List<BigInteger> prg_s_m_n = Crypto.PRG(s_m_n, gradientSize);

					sum_PRG_s_positive = addVectors(sum_PRG_s_positive, prg_s_n_m);
					sum_PRG_s_negative = addVectors(sum_PRG_s_negative, prg_s_m_n);
				}
			}
		}

		// 3. محاسبه گرادیان تجمیع‌شده نهایی (sigma) - برداری
		List<BigInteger> sigma = new ArrayList<>(gradientSize);
		for (int i = 0; i < gradientSize; i++) {
			BigInteger mask = sum_PRG_beta.get(i).add(sum_PRG_s_positive.get(i)).subtract(sum_PRG_s_negative.get(i))
					.mod(Crypto.Q);
			sigma.add(sum_X_hat.get(i).subtract(mask).mod(Crypto.Q));
		}

		// 4. محاسبه اثبات تجمیع‌شده (A, B, L, Q)
		BigInteger A = BigInteger.ONE;
		BigInteger B = BigInteger.ONE;
		BigInteger L = BigInteger.ONE;
		BigInteger Q = BigInteger.ONE;

		for (User u : U3) {
			Round2Output output = round2Outputs.get(u.id);
			if (output != null) {
				A = A.multiply(output.A_n).mod(Crypto.Q);
				B = B.multiply(output.B_n).mod(Crypto.Q);
				L = L.multiply(output.L_n).mod(Crypto.Q);
				Q = Q.multiply(output.Q_n).mod(Crypto.Q);
			}
		}

		ExecutionTimer.addServerTime(Round.R3, System.nanoTime() - startTime);

		return new Round3Output(sigma.get(0), A, B, L, Q, BigInteger.ONE);
	}

	// متد کمکی برای جمع بردارها
	private List<BigInteger> addVectors(List<BigInteger> v1, List<BigInteger> v2) {
		List<BigInteger> result = new ArrayList<>(v1.size());
		for (int i = 0; i < v1.size(); i++) {
			result.add(v1.get(i).add(v2.get(i)).mod(Crypto.Q));
		}
		return result;
	}
}