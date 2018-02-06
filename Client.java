package client;
import static com.sun.xml.internal.stream.writers.XMLStreamWriterImpl.UTF_8;
import java.io.*;
import static java.lang.System.exit;
import java.net.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;

public class Client 
{
	private static Socket serverSocket;
	private static DataOutputStream sendToServer;
	private static DataInputStream recvFromServer;
	public static void main(String[] args) throws IOException, Exception 
	{
            //GENERATING KEYS
                KeyPair keyPair = null;
                try 
                {
                    keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
                } 
                catch (NoSuchAlgorithmException e) 
                {
                    throw new RuntimeException(e);
                }

                PublicKey pbkClient = keyPair.getPublic();      // Public Key
                byte[] PbkClient = pbkClient.getEncoded();      // Public Key 
                PrivateKey pvtClient = keyPair.getPrivate();    // Pvt. Key
                
            //SIGNING
                String signature = sign("AdZSignClient",pvtClient);
           
		try 
		{
			serverSocket = new Socket("localhost",1234);
			sendToServer = new DataOutputStream (serverSocket.getOutputStream());
			recvFromServer = new DataInputStream (serverSocket.getInputStream());
                        
                    //SHARING SIGN
                        sendToServer.writeUTF(signature);
                        String signat = recvFromServer.readUTF();
                
                    //RECEIVING PUBLIC KEY
                        byte[] pbk_Keys = null;
                        int length = recvFromServer.readInt();                      // read length of incoming key
                        if(length>0) 
                        {
                            pbk_Keys = new byte[length];
                            recvFromServer.readFully(pbk_Keys, 0, pbk_Keys.length); // read the key
                        }
                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        X509EncodedKeySpec spec = new X509EncodedKeySpec(pbk_Keys);
                        PublicKey PUBLIC_KEYs = keyFactory.generatePublic(spec);
                        
                    //VERIFYING SIGNATURE
                        boolean isCorrect = verify("AdZSignServer",signat,PUBLIC_KEYs);
                        if(isCorrect)
                        {
                            System.out.println("Signature correct: " + isCorrect);
                            System.out.println("!! Client ready for chat !!");
                        }
                        else
                        {
                            System.out.println("Signature Doesn't Match.");
                            exit(0);
                        }
                        
                    //SENDING PUBLIC KEY
                        sendToServer.writeInt(PbkClient.length);
                        sendToServer.write(PbkClient);
                
                    //RECEIVE MESSAGE
                        Thread thd = new Thread(new Runnable()
                        {
                            public void run()
                            {
                                while(true)
                                {
                                    try
                                    {
                                        String rcvmsg = recvFromServer.readUTF();
                                        String message = decrypt(rcvmsg,pvtClient);
                                        System.out.println("Server: " + message);
                                    }catch(Exception e){}
                                }
                            }
                        });thd.start();
                        
                    //SEND MESSAGE
                        while(true)
                        {
                            String sndmsg = new Scanner(System.in).nextLine();
                            String code = encrypt(sndmsg,PUBLIC_KEYs);
                            sendToServer.writeUTF(code);
                        }
		}catch (Exception e){}
	}
        
        public static String encrypt(String plainText, PublicKey publicKey) throws Exception 
        {
            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));
            return Base64.getEncoder().encodeToString(cipherText);
        }
        public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception 
        {
            byte[] bytes = Base64.getDecoder().decode(cipherText);
            Cipher decriptCipher = Cipher.getInstance("RSA");
            decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(decriptCipher.doFinal(bytes), UTF_8);
        }
        public static String sign(String plainText, PrivateKey privateKey) throws Exception 
        {
            Signature privateSignature = Signature.getInstance("SHA256withRSA");
            privateSignature.initSign(privateKey);
            privateSignature.update(plainText.getBytes(UTF_8));
            byte[] signature = privateSignature.sign();
            return Base64.getEncoder().encodeToString(signature);
        }
        public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception 
        {
            Signature publicSignature = Signature.getInstance("SHA256withRSA");
            publicSignature.initVerify(publicKey);
            publicSignature.update(plainText.getBytes(UTF_8));
            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            return publicSignature.verify(signatureBytes);
        }
        
}