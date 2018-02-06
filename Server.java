package server;
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

public class Server 
{
	private static Socket clientSocket;
	private static ServerSocket serverSocket;
	private static DataOutputStream sendToClient;
	private static DataInputStream recvFromClient;
	public static void main(String[] args) throws Exception 
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
                
                PublicKey pbkServer = keyPair.getPublic();      // Public Key
                byte[] PbkServer = pbkServer.getEncoded();      // Public Key 
                PrivateKey pvtServer = keyPair.getPrivate();    // Pvt. Key
                
            // SIGNING
                String signature = sign("AdZSignServer",pvtServer);
                  
		try 
		{
			serverSocket = new ServerSocket(1234);
			clientSocket = serverSocket.accept();
                        sendToClient = new DataOutputStream (clientSocket.getOutputStream());
			recvFromClient = new DataInputStream (clientSocket.getInputStream());
                        
                    //SHARING SIGN
                        String signat = recvFromClient.readUTF();
                        sendToClient.writeUTF(signature);
                
                    //SENDING PUBLIC KEY
                        sendToClient.writeInt(PbkServer.length);
                        sendToClient.write(PbkServer);
                        
                    //RECEIVING PUBLIC KEY
                        byte[] pbk_Keyc = null;
                        int length = recvFromClient.readInt();                      // read length of incoming key
                        if(length>0) 
                        {
                            pbk_Keyc = new byte[length];
                            recvFromClient.readFully(pbk_Keyc, 0, pbk_Keyc.length); // read the key
                        }
                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        X509EncodedKeySpec spec = new X509EncodedKeySpec(pbk_Keyc);
                        PublicKey PUBLIC_KEYc = keyFactory.generatePublic(spec);
                    
                    //VERIFYING SIGNATURE
                        boolean isCorrect = verify("AdZSignClient",signat,PUBLIC_KEYc);
                        if(isCorrect)
                        {
                            System.out.println("Signature correct: " + isCorrect);
                            System.out.println("!! Server ready for chat !!");
                        }
                        else
                        {
                            System.out.println("Signature Doesn't Match.");
                            exit(0);
                        }
                
                    //Receive Message
                        Thread thd = new Thread(new Runnable()
                        {
                            public void run()
                            {
                                while(true)
                                {
                                    try
                                    {
                                        String rcvmsg = recvFromClient.readUTF();
                                        String message = decrypt(rcvmsg,pvtServer);
                                        System.out.println("Client: " + message);
                                    }catch(Exception e){}
                                }
                            }
                        });thd.start();
			
                    //Send Message    
                        while(true)
                        {
                            String sndmsg = new Scanner(System.in).nextLine();
                            String code = encrypt(sndmsg,PUBLIC_KEYc);
                            sendToClient.writeUTF(code);
                        }
		} catch (Exception e) {}
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