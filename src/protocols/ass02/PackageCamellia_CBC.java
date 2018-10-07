package protocols.ass02;

import java.nio.ByteBuffer;

import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class PackageCamellia_CBC {

    private byte[] key;

    public PackageCamellia_CBC(){
        Security.addProvider(new BouncyCastleProvider());
    }

    public void setKey(String key){
        this.setKey(key.getBytes());
    }

    public void setKey(byte[] key){
        this.key = key;
    }

    public byte[] decrypt(byte[] cipher){
        // Extract the IV value from the package. First 4 bytes are SPI, then 4 sequence numbers, then 16 IV bytes.
        byte[] IV = new byte[16];
        for(int i = 8; i < 24; i++){
            IV[i-8] = cipher[i];
        }

        // Remove headers from the ciphertext to be decrypted
        byte[] ciphertext = new byte[cipher.length-24];
        for(int i = 24; i < cipher.length; i++){
            ciphertext[i-24] = cipher[i];
        }

        // Add padding to be a multiple of 16
        byte[] withPadding = new byte[(int) Math.ceil(((double) ciphertext.length)/16)*16];
        for(int i = 0; i < ciphertext.length; i++){
            withPadding[i] = ciphertext[i];
        }

        // Initialize decrypter
        Key decryptKey = new SecretKeySpec(this.key, "Camellia");
        IvParameterSpec decryptIV = new IvParameterSpec(IV);

        // Start decoding.
        try{
            Cipher aes = Cipher.getInstance("Camellia/CBC/NoPadding");
            aes.init(Cipher.DECRYPT_MODE, decryptKey, decryptIV);
            byte[] decryptedPlaintext = aes.doFinal(withPadding);
            return decryptedPlaintext;
        }
        catch(Exception e){
            System.err.println("Kon niet decrypten");
            System.err.println(e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args){
        PackageCamellia_CBC pack = new PackageCamellia_CBC();
        pack.setKey("YELLOW SUBMARINE");
        //String encryptedPackage = "0000133700000001c4d2789bee3acacb8b2e470e447c49821b7f4f5d0753d3412654b701f7b5f4d9ee3b1994ea2aaea49cbabdbae99207e365a883c79da576437cbf3f611f2d6e69b7ff42c59c6e777cfbe1756cfbbf685ab3b66c3237fb8e6b58be5501";
        String encryptedPackage = "0000053900000001b182132ea244ad520691f5427f4c413870400dbfc5e34bbcde7349d7945660c531b1b6b9ca8621fb6b68cc742a53a8e48f19dbe0a69499e860ade6f7c85be6ecf330cedfccab6562388dd85ba113428b0b6e1fc89d6f21c5baa25f7f";
        byte[] encryptedBytes = PackageCamellia_CBC.hexStringToByteArray(encryptedPackage);

        byte[] decryptedBytes = pack.decrypt(encryptedBytes);
        String text = PackageCamellia_CBC.IPPackageToData(decryptedBytes);

        System.out.println("Encrypted bytes: " + toHex(encryptedBytes));
        System.out.println("Decrypted bytes: " + toHex(decryptedBytes));
        //String text = new String(decryptedBytes);
        System.out.println("Decrypted text: " + text);
    }

    /**
     * Borrowed from https://stackoverflow.com/a/140861/10285297
     * @param s
     * @return
     */
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static String toHex(byte...input){
        String result = "";
        for(byte b:input){
            result += String.format("%02x ", b);
        }
        return result;
    }

    public static String IPPackageToData(byte[] pack){
        // We assume the IP header is the standard 20 bytes long and the UDP header is 8 bytes long.
        // The length byte of the UDP header are the 5the and 6th byte.
        byte[] lengthBytes = new byte[2];
        lengthBytes[0] = pack[24];
        lengthBytes[1] = pack[25];
        short UDPLength = ByteBuffer.wrap(lengthBytes).getShort();
        // Remove UDP headers.
        UDPLength -= 8;

        // Extract the data
        byte[] data = new byte[UDPLength];
        for(int i = 0; i < UDPLength; i++){
            data[i] = pack[i+28];
        }

        // Convert to string
        String result = new String(data);

        return result;
    }
}
