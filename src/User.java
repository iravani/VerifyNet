import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.stream.Collectors;

import com.ui.writers.iravani.talebi.crypto.primitives.data.structure.HashTupple;

public class User {
	public final int id;
	public final BigInteger N_pk, N_sk, P_pk, P_sk;
	public List<BigInteger> localGradient; // x_n (برداری)
	public BigInteger beta_n;
	public BigInteger gamma_n, nu_n; // PF_K1(n)
	private int gradientSize;

	public User(int id, BigInteger n_pk, BigInteger n_sk, BigInteger p_pk, BigInteger p_sk, int gradientSize) {
		this.id = id;
		this.N_pk = n_pk;
		this.N_sk = n_sk;
		this.P_pk = p_pk;
		this.P_sk = p_sk;
		this.gradientSize = gradientSize;
		updateLocalGradient();
	}

	// متد برای به‌روزرسانی گرادیان در هر اپوک
	public void updateLocalGradient() {
		Random rand = new Random();
		this.localGradient = new ArrayList<>(gradientSize);
		for (int i = 0; i < gradientSize; i++) {
			// مقادیر گرادیان باید در مدول Q باشند
			this.localGradient.add(BigInteger.valueOf(id * 10 + rand.nextInt(5)).mod(Crypto.Q));
		}
	}

	// --- راند 1: اشتراک گذاری کلید ---
	public Map<Integer, String> round1_KeySharing(List<User> U1, int t) {
		long startTime = System.nanoTime();

		beta_n = new BigInteger(64, new SecureRandom()).mod(Crypto.Q);

		List<Integer> userIds = U1.stream().map(u -> u.id).collect(Collectors.toList());
		List<ShamirPoint> beta_shares = Crypto.S_share(beta_n, t, userIds);
		List<ShamirPoint> Nsk_shares = Crypto.S_share(N_sk, t, userIds);

		Map<Integer, String> p_n_m = new HashMap<>();
		for (int i = 0; i < U1.size(); i++) {
			User m = U1.get(i);
			BigInteger sharedKey = Crypto.KA_agree(this.P_sk, m.P_pk);

			// (اصلاح شده) ارسال کامل سهم (x و y)
			String message = String.format("%d|%d|%s|%s", this.id, m.id, Nsk_shares.get(i).toString(),
					beta_shares.get(i).toString());
			p_n_m.put(m.id, Crypto.AE_enc(sharedKey, message));
		}

		ExecutionTimer.addClientTime(Round.R1, System.nanoTime() - startTime);
		return p_n_m;
	}

	// --- راند 2: ورودی ماسک‌گذاری شده ---
	public Round2Output round2_MaskedInput(Map<Integer, String> P_m_n, List<User> U2, BigInteger tau, BigInteger delta,
			BigInteger rho, BigInteger gamma_global, BigInteger nu_global) {
		long startTime = System.nanoTime();

		List<BigInteger> x_hat = new ArrayList<>(gradientSize);
		Map<Integer, BigInteger> s_n_m_seeds = new HashMap<>();
		for (User m : U2) {
			if (m.id != this.id) {
				s_n_m_seeds.put(m.id, Crypto.KA_agree(this.N_sk, m.N_pk));
			}
		}

		// --- ماسک‌گذاری برداری ---
		List<BigInteger> prg_beta_vector = Crypto.PRG(beta_n, gradientSize);
		List<BigInteger> prg_s_positive_sum = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));
		List<BigInteger> prg_s_negative_sum = new ArrayList<>(Collections.nCopies(gradientSize, BigInteger.ZERO));

		for (User m : U2) {
			if (m.id == this.id)
				continue;
			BigInteger s_val = s_n_m_seeds.get(m.id);
			List<BigInteger> prg_s_vector = Crypto.PRG(s_val, gradientSize);

			if (this.id < m.id) {
				prg_s_positive_sum = addVectors(prg_s_positive_sum, prg_s_vector);
			} else {
				prg_s_negative_sum = addVectors(prg_s_negative_sum, prg_s_vector);
			}
		}

		for (int i = 0; i < gradientSize; i++) {
			BigInteger masked_x_i = localGradient.get(i).add(prg_beta_vector.get(i)).add(prg_s_positive_sum.get(i))
					.subtract(prg_s_negative_sum.get(i)).mod(Crypto.Q);
			x_hat.add(masked_x_i);
		}

		// --- محاسبه اثبات‌ها (بر اساس المان اول) ---
		// (اصلاح شده) اثبات‌ها باید بر اساس گرادیان واقعی باشند
		BigInteger h_x_simp = localGradient.get(0).multiply(delta).add(rho);
		HashTupple hash_x_simplified = Crypto.HF(h_x_simp);
		BigInteger A_n = hash_x_simplified.h1;
		BigInteger B_n = hash_x_simplified.h2;

		this.gamma_n = new BigInteger(64, new SecureRandom()).mod(Crypto.EXP_MOD);
		this.nu_n = new BigInteger(64, new SecureRandom()).mod(Crypto.EXP_MOD);

		// (اصلاح شده) رفع خطای تقسیم بر d
		BigInteger exponent = gamma_n.multiply(gamma_global).add(nu_n.multiply(nu_global)).mod(Crypto.EXP_MOD);

		HashTupple L_n_exponent = Crypto.HF(exponent.subtract(h_x_simp).mod(Crypto.EXP_MOD).multiply(Crypto.d_inv).mod(Crypto.EXP_MOD));

		BigInteger L_n = L_n_exponent.h1;
		BigInteger Q_n = L_n_exponent.h2;

		ExecutionTimer.addClientTime(Round.R2, System.nanoTime() - startTime);
		return new Round2Output(x_hat, A_n, B_n, L_n, Q_n, BigInteger.ONE);
	}

	// --- راند 3: حذف ماسک ---
	public Round3Input round3_Unmasking(Map<Integer, String> P_m_n, List<User> U3) {
		long startTime = System.nanoTime();
		// (اصلاح شده) ذخیره نقاط شامیر
		Map<Integer, ShamirPoint> Nsk_shares = new HashMap<>();
		Map<Integer, ShamirPoint> beta_shares = new HashMap<>();

		for (User m : U3) {
			// کلید برای رمزگشایی پیام‌هایی که m (فرستنده) برای n (this.id - گیرنده) فرستاده
			// است
			int key = this.id * 1000 + m.id;

			if (P_m_n.containsKey(key)) {
				BigInteger sharedKey = Crypto.KA_agree(this.P_sk, m.P_pk);
				String decrypted = Crypto.AE_dec(sharedKey, P_m_n.get(key));

				if (decrypted != null) {
					String[] parts = decrypted.split("\\|");
					if (parts.length == 6) {
						// id_n(m) | id_m(this) | Nsk.toString() | beta.toString()
						ShamirPoint nsk_point = ShamirPoint.fromString(parts[2] + "|" + parts[3]);
						ShamirPoint beta_point = ShamirPoint.fromString(parts[4] + "|" + parts[5]);

						if (nsk_point != null && beta_point != null) {
							Nsk_shares.put(m.id, nsk_point);
							beta_shares.put(m.id, beta_point);
						}
					}
				}
			}
		}
		ExecutionTimer.addClientTime(Round.R3, System.nanoTime() - startTime);
		return new Round3Input(Nsk_shares, beta_shares);
	}

	// --- راند 4: وارسی (اصلاح شده برای رفع خطا) ---
	public boolean round4_Verification(Round3Output serverResult, BigInteger aggregated_phi) {
		long startTime = System.nanoTime();
		BigInteger A = serverResult.A;
		BigInteger B = serverResult.B;
		BigInteger L = serverResult.L;
		BigInteger proofQ = serverResult.Q;

		// --- شبیه‌سازی وارسی (اصلاح شده) ---

		// (اصلاح شده) 1. eq_A: A^k == B
		// e(A, h) = e(A, g^k) = e(A^k, g)
		// e(g, B)
		// A^k == B (در شبیه‌سازی ما)
		boolean eq_A = A.modPow(Crypto.k, Crypto.Q).equals(B);

		// (اصلاح شده) 2. eq_B: (L^d)^k == Q^d
		// e(g, Q^d) = e(g, (h^exp)^d) = e(g, (g^k)^exp*d) = e(g,g)^(k*exp*d)
		// e(L^d, h) = e((g^exp)^d, g^k) = e(g,g)^(exp*d*k)
		BigInteger L_d = L.modPow(Crypto.d, Crypto.Q);

		BigInteger Q_d = proofQ.modPow(Crypto.d, Crypto.Q);
		boolean eq_B = L_d.modPow(Crypto.k, Crypto.Q).equals(Q_d);

		// (اصلاح شده) 3. eq_C: g^phi == A * L^d
		// Phi = g^phi
		BigInteger Phi_val = Crypto.g.modPow(aggregated_phi.mod(Crypto.EXP_MOD), Crypto.Q);
		// RHS = A * L^d = g^sum(HF) * g^(phi - sum(HF)) = g^phi
		BigInteger RHS_C = A.multiply(L_d).mod(Crypto.Q);
		boolean eq_C = Phi_val.equals(RHS_C);

		boolean result = eq_A && eq_B && eq_C;
		ExecutionTimer.addClientTime(Round.R4, System.nanoTime() - startTime);

		System.out.printf("Debug (User %d): aggregated_phi=%s\n", id, aggregated_phi.mod(Crypto.EXP_MOD).toString());
		System.out.printf("Debug (User %d): Phi_val=%s\n", id, Phi_val.toString());
		System.out.printf("Debug (User %d): RHS_C = A * L^d = %s (A=%s, L_d=%s)\n", id, RHS_C.toString(), A.toString(),
				L_d.toString());

		if (!result) {
			// چاپ جزئیات خطا در صورت شکست
			System.out.printf("User %d (R4): Verification: FAILED (eqA: %b, eqB: %b, eqC: %b)\n", id, eq_A, eq_B, eq_C);
		}
		return result;
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