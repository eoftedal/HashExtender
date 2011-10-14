import java.security.Security;

import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class HashExtender {
	public static void main(String[] args) {
		try {
			Security.addProvider(new BouncyCastleProvider());

			byte[] input = { 'h', 'e', 'l', 'l', 'o' };
			byte[] input2 = { 'w', 'o', 'r', 'l', 'd' };
			if (args.length == 2) {
				input = args[0].getBytes();
				input2 = args[1].getBytes();
			}

			GeneralDigest digester = new SHA1Digest();
			digester.update(input, 0, input.length);
			byte[] digest = new byte[digester.getDigestSize()];
			digester.doFinal(digest, 0);

			System.out.println(new String(Hex.encode(digest)));

			DigestExtender extender = new DigestExtender();
			byte[] newDigest = extender.extend(digester, digest, input2);
			System.out.println(new String(Hex.encode(newDigest)));
			byte[] pad = extender.getPad(digester,input.length);
			
			
			byte[] padded = join(input, pad);
			digester.reset();
			digester.update(padded, 0, padded.length);
			//extender.printParams(digester);
			
			byte[] full = join(padded, input2);
			System.out.println(new String(Hex.encode(full)));
			digester.reset();
			digester.update(full, 0, full.length);
			digester.doFinal(digest, 0);
			System.out.println(new String(Hex.encode(digest)));
			
			
		} catch (Exception ex) {
			ex.printStackTrace();
		}

	}
	private static byte[] join(byte[] bytes1, byte[] bytes2) {
		byte[] result = new byte[bytes1.length + bytes2.length];
		System.arraycopy(bytes1, 0, result, 0, bytes1.length);
		System.arraycopy(bytes2, 0, result, bytes1.length, bytes2.length);
		return result;
	}
}
