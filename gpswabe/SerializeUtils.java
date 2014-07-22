package gpswabe;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.ArrayList;

public class SerializeUtils {

	/* Method has been test okay */
	public static void serializeElement(ArrayList<Byte> arrlist, Element e) {
		byte[] arr_e = e.toBytes();
		serializeUint32(arrlist, arr_e.length);
		byteArrListAppend(arrlist, arr_e);
	}

	/* Method has been test okay */
	public static int unserializeElement(byte[] arr, int offset, Element e) {
		int len;
		int i;
		byte[] e_byte;

		len = unserializeUint32(arr, offset);
		e_byte = new byte[(int) len];
		offset += 4;
		for (i = 0; i < len; i++)
			e_byte[i] = arr[offset + i];
		e.setFromBytes(e_byte);

		return (int) (offset + len);
	}

	public static void serializeString(ArrayList<Byte> arrlist, String s) {
		byte[] b = s.getBytes();
		serializeUint32(arrlist, b.length);
		byteArrListAppend(arrlist, b);
	}

	/*
	 * Usage:
	 * 
	 * StringBuffer sb = new StringBuffer("");
	 * 
	 * offset = unserializeString(arr, offset, sb);
	 * 
	 * String str = sb.substring(0);
	 */
	public static int unserializeString(byte[] arr, int offset, StringBuffer sb) {
		int i;
		int len;
		byte[] str_byte;
		
		len = unserializeUint32(arr, offset);
		offset += 4;
		str_byte = new byte[len];
		for (i = 0; i < len; i++)
			str_byte[i] = arr[offset + i];

		sb.append(new String(str_byte));
		return offset + len;
	}

	public static byte[] serializegpswabePub(gpswabePub pub) {
		ArrayList<Byte> arrlist = new ArrayList<Byte>();

		serializeString(arrlist, pub.pairingDesc);
		serializeElement(arrlist, pub.g);
		serializeElement(arrlist, pub.Y);
		serializeUint32(arrlist, pub.comps.size());

		for (int i=0; i<pub.comps.size();i++){
			serializeString(arrlist, pub.comps.get(i).attr);
			serializeElement(arrlist, pub.comps.get(i).T);
		}
		return Byte_arr2byte_arr(arrlist);
	}

	/*!
	 * Unserialize a public key data structure from a GByteArray. 
	 * 
	 * @param b					GByteArray
	 * @param free				Free flag
	 * @return					Public key data structure
	 */

	public static gpswabePub unserializegpswabePub(byte[] b) {
		gpswabePub pub;
		int offset;
		int len;

		pub = new gpswabePub();
		offset = 0;

		StringBuffer sb = new StringBuffer("");
		offset = unserializeString(b, offset, sb);
		pub.pairingDesc = sb.substring(0);
		
		pub.p=PairingFactory.getPairing("C://Users/Liang/Downloads/jpbc-2.0.0/params/curves/a.properties");
		Pairing pairing=pub.p;

		pub.g = pairing.getG1().newElement();
		pub.Y = pairing.getGT().newElement();

		offset = unserializeElement(b, offset, pub.g);
		offset = unserializeElement(b, offset, pub.Y);
		pub.comps=new ArrayList<gpswabePubComp>();
		len=unserializeUint32(b, offset);
		offset+=4;

		for (int i=0;i<len; i++){
			gpswabePubComp c=new gpswabePubComp();
			StringBuffer sbattr=new StringBuffer("");
			offset=unserializeString(b, offset, sbattr);
			c.attr=sbattr.substring(0);
			c.T=pairing.getG1().newElement();
			offset=unserializeElement(b, offset, c.T);
			pub.comps.add(c);
		}
		return pub;
	}

	/* Method has been test okay */
	public static byte[] serializegpswabeMsk(gpswabeMsk msk) {
		ArrayList<Byte> arrlist = new ArrayList<Byte>();

		serializeElement(arrlist, msk.y);
		serializeUint32(arrlist, msk.comps.size());
		
		for (int i=0; i<msk.comps.size();i++){
			serializeString(arrlist, msk.comps.get(i).attr);
			serializeElement(arrlist, msk.comps.get(i).t);
		}
		return Byte_arr2byte_arr(arrlist);
	}

	/* Method has been test okay */
	public static gpswabeMsk unserializegpswabeMsk(gpswabePub pub, byte[] b) {
		int offset = 0;
		gpswabeMsk msk = new gpswabeMsk();

		msk.y = pub.p.getZr().newElement();

		offset = unserializeElement(b, offset, msk.y);
		msk.comps=new ArrayList<gpswabeMskComp>();
		int len=unserializeUint32(b, offset);
		offset+=4;
		for(int i=0; i<len; i++){
			gpswabeMskComp c=new gpswabeMskComp();
			StringBuffer sb=new StringBuffer("");
			offset=unserializeString(b, offset,sb);
			c.attr=sb.substring(0);
			c.t=pub.p.getZr().newElement();
			offset=unserializeElement(b, offset, c.t);
			msk.comps.add(c);
		}
		return msk;
	}

	/* Method has been test okay */
	public static byte[] serializegpswabePrv(gpswabePrv prv) {
		ArrayList<Byte> arrlist;

		arrlist = new ArrayList<Byte>();
		serializePolicy(arrlist, prv.p);
		return Byte_arr2byte_arr(arrlist);
	}

	/* Method has been test okay */
	public static gpswabePrv unserializegpswabePrv(gpswabePub pub, byte[] b) {
		gpswabePrv prv=new gpswabePrv();
		int offset=0;
		
		prv.p = unserializePolicy(pub, b, offset);
		return prv;
	}
	
	/*!
	 * Serialize a ciphertext key data structure to a GByteArray.
	 *
	 * @param cph				Ciphertext data structure
	 * @return					GByteArray
	 */
	
	public static byte[] gpswabeCphSerialize(gpswabeCph cph) {
		ArrayList<Byte> arrlist = new ArrayList<Byte>();
		serializeElement(arrlist, cph.Ep);
		serializeUint32(arrlist, cph.comps.size());
		for(int i=0;i<cph.comps.size();i++){
			serializeString(arrlist, cph.comps.get(i).attr);
			serializeElement(arrlist, cph.comps.get(i).E);
		}
		return Byte_arr2byte_arr(arrlist);
	}

	/*!
	 * Unserialize a ciphertext data structure from a GByteArray. 
	 *
	 * @param pub				Public key data structure
	 * @param b					GByteArray
	 * @param free				Free flag
	 * @return					Ciphertext key data structure
	 */
	
	public static gpswabeCph gpswabeCphUnserialize(gpswabePub pub, byte[] cphBuf) {
		gpswabeCph cph = new gpswabeCph();
		int offset = 0;

		cph.Ep = pub.p.getGT().newElement();
		offset = unserializeElement(cphBuf, offset, cph.Ep);

		cph.comps=new ArrayList<gpswabeCphComp>();
		int len=unserializeUint32(cphBuf, offset);
		offset+=4;
		for(int i=0; i<len; i++){
			gpswabeCphComp c=new gpswabeCphComp();
			StringBuffer sb=new StringBuffer("");
			offset=unserializeString(cphBuf, offset, sb);
			c.attr=sb.substring(0);
			c.E=pub.p.getG1().newElement();
			offset=unserializeElement(cphBuf, offset, c.E);
			cph.comps.add(c);
		}
		return cph;
	}

	/* Method has been test okay */
	/* potential problem: the number to be serialize is less than 2^31 */
	private static void serializeUint32(ArrayList<Byte> arrlist, int k) {
		int i;
		byte b;

		for (i = 3; i >= 0; i--) {
			b = (byte) ((k & (0x000000ff << (i * 8))) >> (i * 8));
			arrlist.add(Byte.valueOf(b));
		}
	}

	/*
	 * Usage:
	 * 
	 * You have to do offset+=4 after call this method
	 */
	/* Method has been test okay */
	private static int unserializeUint32(byte[] arr, int offset) {
		int i;
		int r = 0;

		for (i = 3; i >= 0; i--)
			r |= (byte2int(arr[offset++])) << (i * 8);
		return r;
	}

	/*!
	 * serialize a policy data structure to a GByteArray.
	 *
	 * @param b					GByteArray.
	 * @param p					Policy data structure
	 * @return					None
	 */
	
	private static void serializePolicy(ArrayList<Byte> arrlist, gpswabePolicy p) {
		serializeUint32(arrlist, p.k);
		if (p.children == null || p.children.length == 0) {
			serializeString(arrlist, p.attr);
			serializeElement(arrlist, p.D);
		} else {
			serializeUint32(arrlist, p.children.length);
			for (int i = 0; i < p.children.length; i++)
				serializePolicy(arrlist, p.children[i]);
		}
	}

	/*!
	 * Unserialize a policy data structure from a GByteArray using the paring parameter
	 * from the public data structure
	 *
	 * @param pub				Public data structure
	 * @param b					GByteArray.
	 * @param offset			offset of policy data structure within GByteArray
	 * @return					Policy data structure
	 */
	private static gpswabePolicy unserializePolicy(gpswabePub pub, byte[] arr,
			int offset) {
		int i;
		int n;
		gpswabePolicy p = new gpswabePolicy();
		p.k = unserializeUint32(arr, offset);
		offset += 4;
		p.attr = "";
	
		/* children */
		n = unserializeUint32(arr, offset);
		System.out.println("number of children is: "+n);
		offset += 4;
		if (n == 0) {
			p.children = null;

			StringBuffer sb = new StringBuffer("");
			offset = unserializeString(arr, offset, sb);
			p.attr = sb.substring(0);

			p.D = pub.p.getG1().newElement();
			
			offset = unserializeElement(arr, offset, p.D);
		} else {
			p.children = new gpswabePolicy[n];
			System.out.println("p.children length is: "+p.children.length);
			for (i = 0; i < n; i++){
				System.out.println("\nbefore assignment offset is :"+offset);
				p.children[i] = unserializePolicy(pub, arr, offset);
			    System.out.println("\n now the offset is:"+offset);
			}
		}
		return p;
	}

	private static int byte2int(byte b) {
		if (b >= 0)
			return b;
		return (256 + b);
	}

	private static void byteArrListAppend(ArrayList<Byte> arrlist, byte[] b) {
		int len = b.length;
		for (int i = 0; i < len; i++)
			arrlist.add(Byte.valueOf(b[i]));
	}

	private static byte[] Byte_arr2byte_arr(ArrayList<Byte> B) {
		int len = B.size();
		byte[] b = new byte[len];

		for (int i = 0; i < len; i++)
			b[i] = B.get(i).byteValue();

		return b;
	}
}
