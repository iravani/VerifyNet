public class ExecutionTimer {
	// server times
	private static long server_R0 = 0;
	private static long server_R1 = 0;
	private static long server_R3 = 0;

	// clients gathering time
	private static long client_R1 = 0;
	private static long client_R2 = 0;
	private static long client_R3 = 0;
	private static long client_R4 = 0;

	public static void reset() {
		server_R0 = 0;
		server_R1 = 0;
		server_R3 = 0;
		client_R1 = 0;
		client_R2 = 0;
		client_R3 = 0;
		client_R4 = 0;
	}

	public static void addServerTime(Round round, long nanos) {
		if (round == Round.R0)
			server_R0 += nanos;
		else if (round == Round.R1)
			server_R1 += nanos;
		else if (round == Round.R3)
			server_R3 += nanos;
	}

	// تغییر یافته برای اضافه کردن همزمان (thread-safe)
	public static synchronized void addClientTime(Round round, long nanos) {
		if (round == Round.R1)
			client_R1 += nanos;
		else if (round == Round.R2)
			client_R2 += nanos;
		else if (round == Round.R3)
			client_R3 += nanos;
		else if (round == Round.R4)
			client_R4 += nanos;
	}

	public static void printTable(double dropoutRate) {
		System.out.println("\n--- Performance Summary Table ---");
		System.out.printf("| %-6s | %-7s | %-12s | %-12s | %-12s | %-12s | %-12s |\n", "Entity", "Dropout",
				"Key Sharing", "Masked Input", "Unmasking", "Verification", "Total");
		System.out.println(
				"|--------|---------|--------------|--------------|--------------|--------------|--------------|");

		double c_r1 = client_R1 / 1_000_000.0;
		double c_r2 = client_R2 / 1_000_000.0;
		double c_r3 = client_R3 / 1_000_000.0;
		double c_r4 = client_R4 / 1_000_000.0;
		double c_total = c_r1 + c_r2 + c_r3 + c_r4;
		System.out.printf("| %-6s | %-7.0f%% | %-12.0f | %-12.0f | %-12.0f | %-12.0f | %-12.0f |\n", "Client",
				dropoutRate * 100, c_r1, c_r2, c_r3, c_r4, c_total);

		double s_r0 = server_R0 / 1_000_000.0;
		double s_r1 = server_R1 / 1_000_000.0;
		double s_r3 = server_R3 / 1_000_000.0;
		double s_total = s_r0 + s_r1 + s_r3;
		System.out.printf("| %-6s | %-7.0f%% | %-12.0f | %-12.0f | %-12.0f | %-12.0f | %-12.0f |\n", "Server",
				dropoutRate * 100, (s_r0 + s_r1), 0.0, s_r3, 0.0, s_total);
	}
}
