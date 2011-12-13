import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.*;
import org.bouncycastle.crypto.digests.*;

import java.lang.reflect.Field;

public class ExtendMD5 {
	public static void main(String[] args) {
	  try {
		Security.addProvider(new BouncyCastleProvider());

		String md5 = args[0];
		int length = Integer.parseInt(args[1]);
		String newData = args[2];	

		byte[] digest = Hex.decode(md5);

		GeneralDigest digester = new MD5Digest();
		
		DigestExtender extender = new DigestExtender();
		byte[] newDigest = extender.extend(digester, digest, newData.getBytes());
		System.out.println("New hash   			        : " + new String(Hex.encode(newDigest)));
		System.out.println("Added attack input          : " + new String(Hex.encode(newData.getBytes())));
		 
		byte[] pad = extender.getPad(digester, length);
		
		System.out.println("Padded block:               : " + url(pad));

		
		
		
	  } catch(Exception e) {
		e.printStackTrace();
	  }
	}
	
	public static String url(byte[] bytes) {
		String r = "";
		for(int i = 0; i < bytes.length; i++) {
			byte[] b = new byte[1];
			b[0] = bytes[i];
			r += "%" + new String(Hex.encode(b));
		}
		return r;
	}

	
	



    public static int byteArrayToInt(byte[] b, int offset) {
        int value = 0;
        for (int i = 0; i < 4; i++) {
            int shift = (4 - 1 - i) * 8;
            value += (b[(3-i) + offset] & 0x000000FF) << shift;
        }
        return value;
    }

	private static void printParams(MD5Digest digest) throws Exception  {
		System.out.println("Bytecount: " +  getField(GeneralDigest.class, "byteCount").get(digest));
		System.out.println("H1: " + Integer.toHexString((Integer)getField(MD5Digest.class, "H1").get(digest)));
		System.out.println("H2: " + Integer.toHexString((Integer)getField(MD5Digest.class, "H2").get(digest)));
		System.out.println("H3: " + Integer.toHexString((Integer)getField(MD5Digest.class, "H3").get(digest)));
		System.out.println("H4: " + Integer.toHexString((Integer)getField(MD5Digest.class, "H4").get(digest)));

	}


	    private static void unpackWord(
	        int     word,
	        byte[]  out,
	        int     outOff)
	    {
	        out[outOff + 0] = (byte) word;
	        out[outOff + 1] = (byte)(word >>> 8);
	        out[outOff + 2] = (byte)(word >>> 16);
	        out[outOff + 3] = (byte)(word >>> 24);
	    }


	private static int pack(byte[] data, int begin) throws Exception {
		return byteArrayToInt(data, begin);
	}

	public static Field getField(Class clazz, String name) {
		Field[] fields = clazz.getDeclaredFields();
		for (int i = 0; i < fields.length; i++) {
			if (fields[i].getName().equals(name)) {
				fields[i].setAccessible(true);
				return fields[i];
			}
		}
		return null;
	}

}
