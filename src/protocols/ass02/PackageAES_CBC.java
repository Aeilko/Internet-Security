package protocols.ass02;

import java.nio.ByteBuffer;
import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class PackageAES_CBC {

    private byte[] key;

    public PackageAES_CBC(){
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
        Key decryptKey = new SecretKeySpec(this.key, "AES");
        IvParameterSpec decryptIV = new IvParameterSpec(IV);

        // Start decoding.
        try{
            Cipher aes = Cipher.getInstance("AES/CBC/NoPadding");
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
        PackageAES_CBC pack = new PackageAES_CBC();
        pack.setKey("YELLOW SUBMARINE");
        //String encryptedPackage = "00000539000000010ebc2167cd4cd1d4ac473f9edd716793cc19fe800d5750f2649efeacafe61a9e5eb6475c6e077744f246f2743dc4bc9138c67170e4fb078ea68165addd0a4e3c1159754820f60f5dff2833279e3d4d153fd8f5c914d7336db47234f6";
        String encryptedPackage = "00000539000000017f7ebbf6f77a85090f01e21039e8ef6c304969fa39fcb638e8bbc454b12a980c2722fb625998d6da3e46cde9cc6b1a6d658ce1da39262f643d536dfdc94c8684f29f566dfe57c473fb41101599bb4141a642bb852808293289f13f24";
        byte[] encryptedBytes = PackageAES_CBC.hexStringToByteArray(encryptedPackage);

        byte[] decryptedBytes = pack.decrypt(encryptedBytes);
        String text = PackageAES_CBC.IPPackageToData(decryptedBytes);

        System.out.println("Encrypted bytes: " + toHex(encryptedBytes));
        System.out.println("Decrypted bytes: " + toHex(decryptedBytes));
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
