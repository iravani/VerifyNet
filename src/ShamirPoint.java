import java.math.BigInteger;

public class ShamirPoint {
		public final BigInteger x;
		public final BigInteger y;

		ShamirPoint(BigInteger x, BigInteger y) {
			this.x = x;
			this.y = y;
		}

		@Override
		public String toString() {
			return x + "|" + y;
		}

		public static ShamirPoint fromString(String s) {
			String[] parts = s.split("\\|");
			if (parts.length != 2)
				return null;
			return new ShamirPoint(new BigInteger(parts[0]), new BigInteger(parts[1]));
		}
	}