import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.stream.Collectors;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;


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
		List<Crypto.ShamirPoint> beta_shares = Crypto.S_share(beta_n, t, userIds);
		List<Crypto.ShamirPoint> Nsk_shares = Crypto.S_share(N_sk, t, userIds);

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
		BigInteger hash_x_simplified = Crypto.HF(localGradient.get(0), delta, rho).mod(Crypto.EXP_MOD);
		BigInteger A_n = Crypto.power(Crypto.g, hash_x_simplified);
		BigInteger B_n = Crypto.power(Crypto.h, hash_x_simplified);

		this.gamma_n = new BigInteger(64, new SecureRandom()).mod(Crypto.EXP_MOD);
		this.nu_n = new BigInteger(64, new SecureRandom()).mod(Crypto.EXP_MOD);

		// (اصلاح شده) رفع خطای تقسیم بر d
		BigInteger exponent = gamma_n.multiply(gamma_global).add(nu_n.multiply(nu_global)).mod(Crypto.EXP_MOD);

		BigInteger L_n_exponent = exponent.subtract(hash_x_simplified).mod(Crypto.EXP_MOD);
		L_n_exponent = L_n_exponent.multiply(Crypto.d_inv).mod(Crypto.EXP_MOD);

		BigInteger L_n = Crypto.power(Crypto.g, L_n_exponent);
		BigInteger Q_n = Crypto.power(Crypto.h, L_n_exponent);

		ExecutionTimer.addClientTime(Round.R2, System.nanoTime() - startTime);
		//return new Round2Output(x_hat, A_n, B_n, L_n, Q_n, BigInteger.ONE);
		// داخل User.round2_MaskedInput — پس از محاسبه hash_x_simplified و L_n_exponent (BigInteger)
		Element zr_hash = Crypto.pairing.getZr().newElement().set(hash_x_simplified.mod(Crypto.EXP_MOD));
		Element A_elem = Crypto.gElement.powZn(zr_hash).getImmutable();
		Element B_elem = Crypto.hElement.powZn(zr_hash).getImmutable();

		BigInteger r = Crypto.pairing.getZr().getOrder();
		Element zr_Lexp = Crypto.pairing.getZr().newElement().set(L_n_exponent.mod(r));
		Element L_elem = Crypto.gElement.powZn(zr_Lexp).getImmutable();
		Element Q_elem = Crypto.hElement.powZn(zr_Lexp).getImmutable();

		return new Round2Output(x_hat, A_elem, B_elem, L_elem, Q_elem, BigInteger.ONE);

	}

	// --- راند 3: حذف ماسک ---
	public Round3Input round3_Unmasking(Map<Integer, String> P_m_n, List<User> U3) {
		long startTime = System.nanoTime();
		// (اصلاح شده) ذخیره نقاط شامیر
		Map<Integer, Crypto.ShamirPoint> Nsk_shares = new HashMap<>();
		Map<Integer, Crypto.ShamirPoint> beta_shares = new HashMap<>();

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
						Crypto.ShamirPoint nsk_point = Crypto.ShamirPoint.fromString(parts[2] + "|" + parts[3]);
						Crypto.ShamirPoint beta_point = Crypto.ShamirPoint.fromString(parts[4] + "|" + parts[5]);

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

	// signature: aggregatedPhi is BigInteger (the computed exponent phi)
	public boolean round4_Verification_withJPBC(
	        Pairing pairing,
	        Element g,
	        Element h,
	        Element A,
	        Element B,
	        Element L,
	        Element proofQ,
	        BigInteger aggregatedPhi) {
		BigInteger r = pairing.getZr().getOrder();
		aggregatedPhi = aggregatedPhi.mod(r);
		
	    Element leftA  = pairing.pairing(A, h);
	    Element rightA = pairing.pairing(g, B);
	    boolean eq_A = leftA.isEqual(rightA);

	    // compute L^d and Q^d safely using Zr elements
	    Element zr_d = pairing.getZr().newElement().set(Crypto.d.mod(pairing.getZr().getOrder()));
	    Element L_d = L.duplicate().powZn(zr_d).getImmutable();
	    Element Q_d = proofQ.duplicate().powZn(zr_d).getImmutable();

	    boolean eq_B = pairing.pairing(L_d, h).isEqual(pairing.pairing(g, Q_d));

	    Element zr_phi = pairing.getZr().newElement().set(aggregatedPhi);
	    Element Phi_val = g.powZn(zr_phi).getImmutable();
	    Element RHS_C = A.duplicate().mul(L_d).getImmutable();
	    boolean eq_C = Phi_val.isEqual(RHS_C);

	    boolean result = eq_A && eq_B && eq_C;
	    // logging...
	    System.out.println("A = "+eq_A+", B = "+eq_B+", C = "+eq_C+", res = "+result);
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