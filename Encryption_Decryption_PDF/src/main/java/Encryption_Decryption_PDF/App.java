package Encryption_Decryption_PDF;

import java.io.File;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.kernel.pdf.EncryptionConstants;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.WriterProperties;

public class App 
{
	
	
	static PrivateKey  privateKey;
	static PublicKey publicKey;
    	static String inputFileName = "C:\\Users\\Hello\\Desktop\\contract.pdf";
    	static String outputFile = "C:\\Users\\Hello\\Desktop\\Encryption_Decryption.pdf"; 
    	static Certificate cert ;
    	static X509Certificate x509Certificate ;
    
    public static void main( String[] args ) 
    {
    	try {
		
		   	
		
		// Create instance of SunPKCS11 provider
     		String pkcs11Config = "C:\\Users\\\\Hello\\eclipse-workspace\\Encryption_Decryption_PDF\\config.cfg";
    		java.io.ByteArrayInputStream pkcs11ConfigStream = new java.io.ByteArrayInputStream(pkcs11Config.getBytes());
    		// Create a Provider for accessing the USB token by supplying the configuration.
	    	sun.security.pkcs11.SunPKCS11 providerPKCS11 = new sun.security.pkcs11.SunPKCS11(pkcs11Config);
	    	java.security.Security.addProvider(providerPKCS11);   

	   	// Create the Keystore for accessing certificates in the USB device by supplying the PIN.
	    	KeyStore.CallbackHandlerProtection chp = new KeyStore.CallbackHandlerProtection(new MyGuiCallbackHandler() {});
	    	KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11", null, chp);
	    	KeyStore keyStore = builder.getKeyStore();
         
	    
	 
	    
	      	// Enumerate items (certificates and private keys) in the KeyStore
          	java.util.Enumeration<String> aliases = keyStore.aliases();	 
          	String alias = null;
		
		
		  while (aliases.hasMoreElements()) {


		     alias = aliases.nextElement();


		     cert = keyStore.getCertificate(alias);
		     x509Certificate =  (X509Certificate)cert ;


		    // x509Certificate.getKeyUsage()[0]  Check whether the certificate has : digitalSignature         
		    if( x509Certificate.getKeyUsage()[2] == true) {

		    Key key = keyStore.getKey(alias, null); // Here I try to access the private key of my hardware certificate
		    privateKey  =  (PrivateKey )key ; 
		    publicKey = x509Certificate.getPublicKey();


		    break;

		    }     

		}


		  File file = new File(outputFile);
		  file.getParentFile().mkdirs();
		  new App().manipulatePdf(outputFile);  
		  System.out.println(" The PDF file has been successfully encrypted ");


	}
		
	catch(Exception e ){
			
		e.printStackTrace();
			
	}	
 }
    
    
    
    
    protected void manipulatePdf(String dest) throws Exception {
      
    	Security.addProvider(new BouncyCastleProvider());

        PdfDocument pdfDoc = new PdfDocument(
                new PdfReader(inputFileName),
                new PdfWriter(dest, new WriterProperties().setPublicKeyEncryption(
                        new Certificate[] {x509Certificate},
                        new int[] {EncryptionConstants.ALLOW_PRINTING},
                        // Due to import control restrictions by the governments of a few countries,
                        // the encryption libraries shipped by default with the Java SDK restrict
                        // the length, and as a result the strength, of encryption keys. Be aware
                        // that in this sample you need to replace the default security JARs in your
                        // Java installation with the Java Cryptography Extension (JCE) Unlimited
                        // Strength Jurisdiction Policy Files. These JARs are available for download
                        // from http://java.oracle.com/ in eligible countries.
                        EncryptionConstants.ENCRYPTION_AES_256))
        );
        pdfDoc.close();

    }
}
