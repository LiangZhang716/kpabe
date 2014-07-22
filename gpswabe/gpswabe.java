package gpswabe;

import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pbc.curve.PBCTypeACurveGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
public class gpswabe {
	private static String curveParams = "type a\n"
			+ "q 87807107996633125224377819847540498158068831994142082"
			+ "1102865339926647563088022295707862517942266222142315585"
			+ "8769582317459277713367317481324925129998224791\n"
			+ "h 12016012264891146079388821366740534204802954401251311"
			+ "822919615131047207289359704531102844802183906537786776\n"
			+ "r 730750818665451621361119245571504901405976559617\n"
			+ "exp2 159\n" + "exp1 107\n" + "sign1 1\n" + "sign0 1\n";
	
	/*!
	 * Generate public and master key with the provided attributes list.
	 *
	 * @param pub			Pointer to the public key data structure
	 * @param msk			Pointer to the master key data structure
	 * @param attributes	Attributes list
	 * @return				none.
	 */

	public static void setup(gpswabePub pub, gpswabeMsk msk, String[] attrs) {
		Element tmp;
		pub.pairingDesc=curveParams; 
		pub.p=PairingFactory.getPairing("C://Users/Liang/Downloads/jpbc-2.0.0/params/curves/a.properties");
		Pairing pairing=pub.p;
		
		pub.g=pairing.getG1().newElement();
		tmp=pairing.getG1().newElement();
		pub.Y=pairing.getGT().newElement();
		msk.y=pairing.getZr().newElement();
	
		pub.comps=new ArrayList<gpswabePubComp>();
		msk.comps=new ArrayList<gpswabeMskComp>();
		
		msk.y.setToRandom();
		pub.g.setToRandom();
		
		tmp=pub.g.duplicate();
		tmp.powZn(msk.y);
		
		pub.Y = pairing.pairing(pub.g, tmp);
		int len=attrs.length;
		for (int i=0; i<len; i++){
			gpswabePubComp TA=new gpswabePubComp();
			gpswabeMskComp ta=new gpswabeMskComp();
			TA.attr=attrs[i];
			ta.attr=TA.attr;
			
			ta.t=pairing.getZr().newElement();
			TA.T=pairing.getG1().newElement();
			ta.t.setToRandom();
			TA.T=pub.g.duplicate();
			(TA.T).powZn(ta.t);
			pub.comps.add(TA);
			msk.comps.add(ta);
		}
	}
	
	public static gpswabePrv keygen(gpswabePub pub, gpswabeMsk msk, String policy) throws Exception{
		gpswabePrv prv=new gpswabePrv();
		prv.p=parsePolicyPostfix(policy);
		if(prv.p==null){
			System.out.println("Policy cannot be found!");
			return null;
		}
		else {
			fillPolicy(prv.p, pub, msk, msk.y);
			return prv;
			}
	}
	
	/*!
	 * Generate a Policy tree from the input policy string.
	 *
	 * @param s				Policy string
	 * @return				Policy root node data structure
	 */

	private static gpswabePolicy parsePolicyPostfix(String s) throws Exception {
		String[] toks;
		String tok;
		ArrayList<gpswabePolicy> stack = new ArrayList<gpswabePolicy>();
		gpswabePolicy root;

		toks = s.split(" ");

		int toks_cnt = toks.length;
		for (int index = 0; index < toks_cnt; index++) {
			int i, k, n;

			tok = toks[index];
			if (!tok.contains("of")) {
				stack.add(baseNode(1, tok));
			} else {
				gpswabePolicy node;

				/* parse "kofn" node */
				String[] k_n = tok.split("of");
				k = Integer.parseInt(k_n[0]);
				n = Integer.parseInt(k_n[1]);
				
				if (k < 1) {
					System.out.println("error parsing " + s
							+ ": trivially satisfied operator " + tok);
					return null;
				} else if (k > n) {
					System.out.println("error parsing " + s
							+ ": unsatisfiable operator " + tok);
					return null;
				} else if (n == 1) {
					System.out.println("error parsing " + s
							+ ": indentity operator " + tok);
					return null;
				} else if (n > stack.size()) {
					System.out.println("error parsing " + s
							+ ": stack underflow at " + tok);
					return null;
				}

				/* pop n things and fill in children */
				node = baseNode(k, null);
				node.children = new gpswabePolicy[n];

				for (i = n - 1; i >= 0; i--)
					node.children[i] = stack.remove(stack.size() - 1);

				/* push result */
				stack.add(node);
			}
		}

		if (stack.size() > 1) {
			System.out.println("error parsing " + s
					+ ": extra node left on the stack");
			return null;
		} else if (stack.size() < 1) {
			System.out.println("error parsing " + s + ": empty policy");
			return null;
		}

		root = stack.get(0);
		return root;
	}
	

	/*!
	 * Generate a Policy tree from the input policy string.
	 *
	 * @param s				Policy string
	 * @return				Policy root node data structure
	 */

	private static gpswabePolicy baseNode(int k, String s) {
		gpswabePolicy p = new gpswabePolicy();

		p.k = k;
		if (!(s == null))
			p.attr = s;
		else
			p.attr = null;
		p.q = null;
		return p;
	}

	/*!
	 * Routine to fill out the Policy tree
	 *
	 * @param P				Pointer to Root node policy data structure
	 * @param pub			Public key
	 * @param msk			Master key
	 * @param e				Root secret
	 * @return				None
	 */
	private static void fillPolicy(gpswabePolicy p, gpswabePub pub, gpswabeMsk msk, Element e)
			throws NoSuchAlgorithmException {
		int i;
		Element r, t, a;
		Pairing pairing = pub.p;
		r = pairing.getZr().newElement();
		t = pairing.getZr().newElement();
		a = pairing.getZr().newElement();

		p.q = randPoly(p.k - 1, e);

		if (p.children == null || p.children.length == 0) {
			p.D = pairing.getG1().newElement();
			
			for(i=0; i<msk.comps.size();i++){
				if(msk.comps.get(i).attr.compareTo(p.attr)==0){
					a=p.q.coef[0].duplicate();
					a.div(msk.comps.get(i).t);
					p.D=pub.g.duplicate();
					p.D.powZn(a);
					break;
				}
				else{
					if(i==msk.comps.size()-1){
						System.err.println("Check your attribute universe. Certain attribute not included!");
						System.exit(0);
					}
				}
			}
		} else {
			for (i = 0; i < p.children.length; i++) {
				r.set(i + 1);
				evalPoly(t, p.q, r);
				fillPolicy(p.children[i], pub, msk, t);
			}
		}

	}
	
	/*!
	 * Compute the constant value of the child node's Lagrange basis polynomial,
	 *
	 * @param r				Constant value of this child node's Lagrange basis polynomial
	 * @param q				Pointer to the lagrange basis polynomial of parent node
	 * @param x				index of this child node in its parent node
	 * @return				None
	 */
	private static void evalPoly(Element r, gpswabePolynomial q, Element x) {
		int i;
		Element s, t;

		s = r.duplicate();
		t = r.duplicate();

		r.setToZero();
		t.setToOne();

		for (i = 0; i < q.deg + 1; i++) {
			/* r += q->coef[i] * t */
			s = q.coef[i].duplicate();
			s.mul(t); 
			r.add(s);

			/* t *= x */
			t.mul(x);
		}

	}
	
	/*!
	 * Randomly generate the Lagrange basis polynomial base on provided constant value
	 *
	 * @param deg			Degree of the lagrange basis polynomial
	 * @param zero_val		Constant value of the lagrange basis polynomial
	 * @return				Lagrange basis polynomial data structure
	 */

	private static gpswabePolynomial randPoly(int deg, Element zeroVal) {
		int i;
		gpswabePolynomial q = new gpswabePolynomial();
		q.deg = deg;
		q.coef = new Element[deg + 1];

		for (i = 0; i < deg + 1; i++)
			q.coef[i] = zeroVal.duplicate();

		q.coef[0].set(zeroVal);

		for (i = 1; i < deg + 1; i++)
			q.coef[i].setToRandom();

		return q;
	}
	
	private static void elementFromString(Element h, String s)
			throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] digest = md.digest(s.getBytes());
		h.setFromHash(digest, 0, digest.length);
	}
	
	/*!
	 * Encrypt a secret message with the provided attributes list, return a ciphertext.
	 *
	 * @param pub			Public key structure
	 * @param m				Secret Message
	 * @param attributes	Attributes list
	 * @return				Ciphertext structure
	 */
	public static gpswabeCph enc(gpswabePub pub,Element m, String[] attrs)throws Exception{
		gpswabeCph cph=new gpswabeCph();
		Element s;
		int i;
		//initialize
		Pairing pairing=pub.p;
		s=pairing.getZr().newElement();
		m=pairing.getGT().newElement();
		cph.Ep=pairing.getGT().newElement();
		//compute
		m.setToRandom();
		s.setToRandom();
		cph.Ep=pub.Y.duplicate();
		cph.Ep.powZn(s);
		cph.Ep.mul(m);
		cph.comps=new ArrayList<gpswabeCphComp>();
		int len=attrs.length;
		for (i=0;i<len;i++){
			gpswabeCphComp c=new gpswabeCphComp();
			c.attr=attrs[i];
			c.E=pairing.getG1().newElement();
			for (int j=0;j<pub.comps.size(); j++){
				String pubAttr=pub.comps.get(j).attr;
				if (pubAttr.compareTo(c.attr)==0){
					c.E=pub.comps.get(j).T.duplicate();
					c.E.powZn(s);
					break;
				}
				else{
					if(j==(pub.comps.size()-1)){
						System.out.println("Check your attribute universe. Certain attribute is not included.");
						System.exit(0);
					}
				}
			}
			cph.comps.add(c);
		}
		return cph;
	}
	
	/*Pick a random group element and encrypt it under the attributes
	 * The resulting ciphertext is return and the Element given as an argument
	 */
	public static gpswabeCphKey enc(gpswabePub pub, String[] attrs)throws Exception{
		gpswabeCphKey cphKey=new gpswabeCphKey();
		gpswabeCph cph=new gpswabeCph();
		Element s;
		Element m;
		int i;
		//initialize
		Pairing pairing=pub.p;
		s=pairing.getZr().newElement();
		m=pairing.getGT().newElement();
		cph.Ep=pairing.getGT().newElement();
		//compute
		m.setToRandom();
		s.setToRandom();
		Element duplicate=pub.Y.duplicate();
		cph.Ep=duplicate.powZn(s);
		cph.Ep=cph.Ep.mul(m);
		cph.comps=new ArrayList<gpswabeCphComp>();
		int len=attrs.length;
		for (i=0;i<len;i++){
			gpswabeCphComp c=new gpswabeCphComp();
			c.attr=attrs[i];
			c.E=pairing.getG1().newElement();
			for (int j=0;j<pub.comps.size(); j++){
				String pubAttr=pub.comps.get(j).attr;
				if (pubAttr.compareTo(c.attr)==0){
					Element dupl=pub.comps.get(j).T.duplicate();
					c.E=dupl.powZn(s);
					break;
				}
				else{
					if(j==(pub.comps.size()-1)){
						System.out.println("Check your attribute universe. Certain attribute is not included.");
					}
				}
			}
			cph.comps.add(c);
		}
		cphKey.cph=cph;
		cphKey.key=m; /*used for AES encryption*/
		return cphKey;
	}
	
	/*!
	 * Check whether the attributes in the ciphertext data structure can
	 * access the root secret in the policy data structure, and mark all
	 * possible path
	 *
	 * @param p				Policy node data structure (root)
	 * @param cph			Ciphertext data structure
	 * @param oub			Public key data structure
	 * @return				None
	 */
	private static void checkSatisfy(gpswabePolicy p, gpswabeCph cph, gpswabePub pub) {
		int i, l;
		String cphAttr;
		String pubAttr;

		p.satisfiable = false;
		if (p.children == null || p.children.length == 0) {
			for (i = 0; i < cph.comps.size(); i++) {
				cphAttr = cph.comps.get(i).attr;
				// System.out.println("cphAttr:" + cphAttr);
				// System.out.println("p.attr" + p.attr);
				if (cphAttr.compareTo(p.attr) == 0) {
					// System.out.println("=satisfy=");
					p.satisfiable = true;
					p.attri = i;
					break;
				}
			}
			for(i=0;i<pub.comps.size();i++){
				pubAttr=pub.comps.get(i).attr;
				if(pubAttr.compareTo(p.attr)==0){
					break;
				}
				else{
					if(i==pub.comps.size()-1){
						System.out.println("Check your attribute universe. Certain attribute is not included!");
						break;
					}
				}
			}
		} else {
			for (i = 0; i < p.children.length; i++)
				checkSatisfy(p.children[i], cph, pub);

			l = 0;
			for (i = 0; i < p.children.length; i++)
				if (p.children[i].satisfiable)
					l++;

			if (l >= p.k)
				p.satisfiable = true;
		}
	}
	
	/*!
	 * Choose the path with minimal leaves node from all possible path which are marked as satisfiable
	 * Mark the respective "min_leaves" element in the policy node data structure
	 *
	 * @param p				Policy node data structure (root)
	 * @return				None
	 */
	private static void pickSatisfyMinLeaves(gpswabePolicy p) {
		int i, k, l, c_i;
		int len;
		List<Integer> c = new ArrayList<Integer>();

		assert(p.satisfiable);
		if (p.children == null || p.children.length == 0)
			p.min_leaves = 1;
		else {
			len = p.children.length;
			for (i = 0; i < len; i++)
				if (p.children[i].satisfiable)
					pickSatisfyMinLeaves(p.children[i]);

			for (i = 0; i < len; i++)
				c.add(i);

			Collections.sort(c, new IntegerComparator(p));

			p.satl = new ArrayList<Integer>();
			p.min_leaves = 0;
			l = 0;

			for (i = 0; i < len && l < p.k; i++) {
				c_i = c.get(i).intValue(); /* c[i] */
				if (p.children[c_i].satisfiable) {
					l++;
					p.min_leaves += p.children[c_i].min_leaves;
					k = c_i + 1;
					p.satl.add(k);
				}
			}
			assert(l==p.k);
		}
	}
	
	/*!
	 * Compute Lagrange coefficient
	 *
	 * @param r				Lagrange coefficient
	 * @param s				satisfiable node set
	 * @param i				index of this node in the satisfiable node set
	 * @return				None
	 */
	private static void lagrangeCoef(Element r, ArrayList<Integer> s, int i) {
		int j, k;
		Element t;

		t = r.duplicate();

		r.setToOne();
		for (k = 0; k < s.size(); k++) {
			j = s.get(k).intValue();
			if (j == i)
				continue;
			t.set(-j);
			r.mul(t); /* num_muls++; */
			t.set(i - j);
			t.invert();
			r.mul(t); /* num_muls++; */
		}
	}
	
	/*!
	 * DecryptNode algorithm for root secret
	 *
	 * @param r				Root secret
	 * @param p				Policy node dtat structure(root)
	 * @param cph			Ciphertext data structure
	 * @param pub			Public key data structure
	 * @return				None
	 */
	private static void decFlatten(Element r, gpswabePolicy p, gpswabeCph cph,
			gpswabePub pub) {
		Element one;
		one = pub.p.getZr().newElement();
		one.setToOne();
		r.setToOne();

		decNodeFlatten(r, one, p, cph, pub);
	}

	
	private static void decNodeFlatten(Element r, Element exp, gpswabePolicy p,
			gpswabeCph cph, gpswabePub pub) {
		assert(p.satisfiable);
		if (p.children == null || p.children.length == 0)
			decLeafFlatten(r, exp, p, cph, pub);
		else
			decInternalFlatten(r, exp, p, cph, pub);
	}

	private static void decLeafFlatten(Element r, Element exp, gpswabePolicy p,
			gpswabeCph cph, gpswabePub pub) {
		gpswabeCphComp c;
		Element s;

		c = cph.comps.get(p.attri);

		s = pub.p.getGT().newElement();

		s = pub.p.pairing(p.D, c.E); /* num_pairings++; */
		s.powZn(exp); /*num_exps++;*/
		r.mul(s); /*num_muls++;*/
	}

	private static void decInternalFlatten(Element r, Element exp,
			gpswabePolicy p, gpswabeCph cph, gpswabePub pub) {
		int i;
		Element t, expnew;

		t = pub.p.getZr().newElement();
		expnew = pub.p.getZr().newElement();

		for (i = 0; i < p.satl.size(); i++) {
			lagrangeCoef(t, p.satl, (p.satl.get(i)).intValue());
			expnew = exp.duplicate();
			expnew.mul(t);
			decNodeFlatten(r, expnew, p.children[p.satl.get(i)-1],cph, pub);
		}
	}

	
	public static Element dec(gpswabePub pub, gpswabePrv prv, gpswabeCph cph){
		Element Ys;
		Element m;
		Pairing pairing=pub.p;
		m=pairing.getGT().newElement();
		Ys=pairing.getGT().newElement();
		checkSatisfy(prv.p, cph, pub);
		if(!prv.p.satisfiable){
			System.out.println("Cannot decrypt.");
			return null;
		}
		pickSatisfyMinLeaves(prv.p);
		decFlatten(Ys, prv.p, cph, pub);
		Element tmp=cph.Ep.duplicate();
		m=tmp.div(Ys);
		return m;
	}
	
	
	private static class IntegerComparator implements Comparator<Integer> {
		gpswabePolicy policy;

		public IntegerComparator(gpswabePolicy p) {
			this.policy = p;
		}

		@Override
		public int compare(Integer o1, Integer o2) {
			int k, l;

			k = policy.children[o1.intValue()].min_leaves;
			l = policy.children[o2.intValue()].min_leaves;

			return	k < l ? -1 : 
					k == l ? 0 : 1;
		}
	}
}
