import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.*;
import org.bouncycastle.crypto.digests.*;
import java.net.URLDecoder;

public class TestSignature {
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		String secret = "HackPra!";
		String validId  = "id1";

		if (args.length == 2) {
			String signature = args[1];
			String parameters = URLDecoder.decode(args[0]).replace("&", "").replace("=", "");
			if (signature.equals(hash(secret + parameters))) {
				String ar = args[0].replaceFirst("(.*\\&)?(id=[0-9]+)(\\&.*)?", "$2");
				System.out.println("Showing secret data for " + ar + ":\n-");
				if (ar.equals("id=1")) {
					System.out.println("This is not very secret");
				} else {
					System.out.println("Wow! This is so secret!");
				}
			} else {
				System.out.println("Error validating signature. Access denied");
			}
			
		} else {
			System.out.println("Public data: id=1 signature=" + hash(secret + validId));
		}
	
	}
	
	public static String hash(String data) {
		byte[] input = data.getBytes();
		MD5Digest md5 = new MD5Digest();
		md5.update(input, 0, input.length);
		byte[] digest = new byte[md5.getDigestSize()];
		md5.doFinal(digest, 0);
		return new String(Hex.encode(digest));
	
	}
	
}