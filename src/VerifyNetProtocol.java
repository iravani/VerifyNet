// =====================================================================
//  توابع و ساختارهای داده پایه (اصلاح شده)
// =====================================================================

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;

enum Round {
	R0, R1, R2, R3, R4
}

public class VerifyNetProtocol {

	private static final int NUM_EPOCHS = 1;
	private static final int GRADIENT_SIZE = 1000;
	private static final double DROPOUT_RATE = 0.1;
	private static final int USER_COUNT = 100;
	private static final int SHAMIR_THRESHOLD = 50;

	public static List<User> filterUsersByDropout(List<User> users, double rate) {
		if (rate == 0.0)
			return new ArrayList<>(users);
		Random rand = new Random();
		return users.stream().filter(u -> rand.nextDouble() >= rate).collect(Collectors.toList());
	}

	public static void main(String[] args) {
		SecureRandom secRand = new SecureRandom();

		// TA : Generate Keys
		List<User> allUsers = new ArrayList<>();
		for (int i = 1; i <= USER_COUNT; i++) {
			BigInteger N_sk = new BigInteger(Crypto.LAMDA, secRand).mod(Crypto.EXP_MOD);
			BigInteger P_sk = new BigInteger(Crypto.LAMDA, secRand).mod(Crypto.EXP_MOD);
			BigInteger N_pk = Crypto.power(Crypto.g, N_sk);
			BigInteger P_pk = Crypto.power(Crypto.g, P_sk);
			allUsers.add(new User(i, N_pk, N_sk, P_pk, P_sk, GRADIENT_SIZE));
		}
		BigInteger delta = new BigInteger(64, secRand).mod(Crypto.Q);
		BigInteger rho = new BigInteger(64, secRand).mod(Crypto.Q);
		BigInteger gamma_global = new BigInteger(64, secRand).mod(Crypto.EXP_MOD);
		BigInteger nu_global = new BigInteger(64, secRand).mod(Crypto.EXP_MOD);

		// main epoch loop
		for (int epoch = 1; epoch <= NUM_EPOCHS; epoch++) {
			ExecutionTimer.reset();
			System.out.println("\n=========================================");
			System.out.printf("--- EPOCH %d / %d ---\n", epoch, NUM_EPOCHS);
			System.out.println("=========================================");

			Server server = new Server();

			// --- R0: Initialization (with Dropout) ---
			System.out.println("--- R0: Initialization ---");
			server.round0_Initialization(allUsers, SHAMIR_THRESHOLD, DROPOUT_RATE, GRADIENT_SIZE);
			List<User> U1 = server.U1; // users that passed R0

			if (U1.size() < SHAMIR_THRESHOLD) {
				System.out.printf("Skipping epoch %d: Not enough users after R0 dropout (%d < t=%d).\n", epoch,
						U1.size(), SHAMIR_THRESHOLD);
				continue;
			}

			// --- R1: Key Sharing (with Dropout) ---
			System.out.println("\n--- R1: Key Sharing ---");
			List<User> U1_R1 = filterUsersByDropout(U1, DROPOUT_RATE);
			if (U1_R1.size() < SHAMIR_THRESHOLD) {
				System.out.printf("Skipping epoch %d: Not enough users after R1 dropout (%d < t=%d).\n", epoch,
						U1_R1.size(), SHAMIR_THRESHOLD);
				continue;
			}

			Map<Integer, Map<Integer, String>> all_P_n_m = new HashMap<>();
			for (User u : U1_R1) {
				all_P_n_m.put(u.id, u.round1_KeySharing(U1_R1, SHAMIR_THRESHOLD));
			}
			Map<Integer, String> P_m_n_all = server.round1_KeySharing(all_P_n_m);

			// --- R2: Masked input (with Dropout) ---
			System.out.println("\n--- R2: Masked Input ---");
			List<User> U2 = filterUsersByDropout(U1_R1, DROPOUT_RATE);
			if (U2.size() < SHAMIR_THRESHOLD) {
				System.out.printf("Skipping epoch %d: Not enough users after R2 dropout (%d < t=%d).\n", epoch,
						U2.size(), SHAMIR_THRESHOLD);
				continue;
			}

			Map<Integer, Round2Output> round2Outputs = new HashMap<>();
			for (User u : U2) {
				Round2Output r2out = u.round2_MaskedInput(P_m_n_all, U2, server.tau, delta, rho, gamma_global,
						nu_global);
				round2Outputs.put(u.id, r2out);
			}

			// --- R3: Unmasking (with Dropout) ---
			System.out.println("\n--- R3: Unmasking and Aggregation ---");
			List<User> U3 = filterUsersByDropout(U2, DROPOUT_RATE);
			if (U3.size() < SHAMIR_THRESHOLD) {
				System.out.printf("Skipping epoch %d: Not enough users after R3 dropout (%d < t=%d).\n", epoch,
						U3.size(), SHAMIR_THRESHOLD);
				continue;
			}

			// calculate phi based on U3
			BigInteger aggregated_phi_actual = BigInteger.ZERO;
			for (User u : U3) {
				// ensure that U3 users where in U2
				// (gamma_n and nu_n are set in R2)
				if (round2Outputs.containsKey(u.id)) {
					BigInteger exponent = u.gamma_n.multiply(gamma_global).add(u.nu_n.multiply(nu_global))
							.mod(Crypto.EXP_MOD);
					aggregated_phi_actual = aggregated_phi_actual.add(exponent).mod(Crypto.EXP_MOD);
				}
			}

			// update local gradients of users
			U3.forEach(User::updateLocalGradient);

			Map<Integer, Round3Input> round3Inputs = new HashMap<>();
			for (User u : U3) {
				round3Inputs.put(u.id, u.round3_Unmasking(P_m_n_all, U3));
			}

			// ensure that server only uses R2Outputs users of U3
			Map<Integer, Round2Output> finalRound2Outputs = new HashMap<>();
			for (User u : U3) {
				if (round2Outputs.containsKey(u.id)) {
					finalRound2Outputs.put(u.id, round2Outputs.get(u.id));
				}
			}

			Round3Output finalResult = server.round3_UnmaskingAndAggregation(finalRound2Outputs, round3Inputs, U3,
					SHAMIR_THRESHOLD);
			System.out.printf("Server (R3): Final Aggregated Gradient (Sigma[0]): %s\n", finalResult.sigma.toString());

			// --- R4: verification ---
			System.out.println("\n--- R4: Verification ---");
			int successCount = 0;
			for (User u : U3) {
				if (u.round4_Verification(finalResult, aggregated_phi_actual)) {
					successCount++;
				}
			}
			System.out.printf("--- R4 Summary: %d / %d users PASSED verification.\n", successCount, U3.size());

			// --- print the time table ---
			ExecutionTimer.printTable(DROPOUT_RATE);
		}
	}
}