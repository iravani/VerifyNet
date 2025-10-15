import java.math.BigInteger;

import com.ui.writers.iravani.talebi.crypto.primitives.schemes.ElGemal;
import com.ui.writers.iravani.talebi.crypto.primitives.data.structure.ElGemalEncryptedData;

public class Main {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		BigInteger m = BigInteger.valueOf(440);
		ElGemal elGemal = new ElGemal(128);
		
		ElGemalEncryptedData c = elGemal.Enc(m);
		c.print();
		System.out.println(elGemal.Dec(c));
	}

}
