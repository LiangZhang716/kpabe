package gpswabe;

import java.util.ArrayList;
import it.unisa.dia.gas.jpbc.Element;

public class gpswabePolicy {
	/*serialized*/
	/* k=1 if leaf, otherwise threshold */
	int k;
	/* attribute string if leaf, otherwise null */
	String attr;
	Element D;			/* G_1 only for leaves */
	/* array of gpswabePolicy and length is 0 for leaves */
	gpswabePolicy[] children;

	/* only used during encryption */
	gpswabePolynomial q;

	/* only used during decryption */
	boolean satisfiable;
	int min_leaves;
	int attri;
	ArrayList<Integer> satl = new ArrayList<Integer>();
}