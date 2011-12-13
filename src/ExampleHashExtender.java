import java.security.Security;

import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class ExampleHashExtender {
	public static void main(String[] args) {
		try {
			Security.addProvider(new BouncyCastleProvider());

			byte[] input = "Hello".getBytes();
			byte[] input2 = "World".getBytes();
			if (args.length == 2) {
				input = args[0].getBytes();
				input2 = args[1].getBytes();
			}

			//Modify here if you want to use MD5, SHA1 or SHA256
			GeneralDigest digester = new SHA1Digest();

			//Do a hash of the input
			digester.update(input, 0, input.length);
			byte[] digest = new byte[digester.getDigestSize()];
			digester.doFinal(digest, 0);
			System.out.println("Original hash: " + new String(Hex.encode(digest)));

			//Create an extended hash
			DigestExtender extender = new DigestExtender();
			byte[] newDigest = extender.extend(digester, digest, input2);
			System.out.println("Extended hash: " + new String(Hex.encode(newDigest)));

			//Calculate the padding and build a hash from scratch
			byte[] pad = extender.getPad(digester,input.length);
			byte[] padded = join(input, pad);
			digester.reset();
			digester.update(padded, 0, padded.length);
			System.out.println("Padding      : " + new String(Hex.encode(pad)));
			byte[] full = join(padded, input2);
			System.out.println("Full input   : " + new String(Hex.encode(full)));
			digester.reset();
			digester.update(full, 0, full.length);
			digester.doFinal(digest, 0);
			System.out.println("Full hash    : " + new String(Hex.encode(digest)));
			System.out.println("If everything went ok, the full hash should be equal to the extended hash");
			
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
