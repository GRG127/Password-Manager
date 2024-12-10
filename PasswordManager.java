import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;
import java.security.SecureRandom;

public class PasswordManager {
    
    private static final String encryptionKey = "mysecretkey12345";
    private static final String salt = "saltykey"; 
    
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

       
        System.out.println("Setting up your Master Password");
        System.out.print("Enter your master password: ");
        String masterPassword = scanner.nextLine();


        System.out.println("Master password setup complete.");
        System.out.println("You can now securely manage your passwords.");

        SecretKey aesKey = getKeyFromPassword(masterPassword);
        

        while (true) {
            System.out.println("\n1. Add New Credentials");
            System.out.println("2. Retrieve Credentials");
            System.out.println("3. Exit");
            System.out.print("Choose an option: ");
            int option = scanner.nextInt();
            scanner.nextLine(); 

            if (option == 1) {
                addNewCredentials(scanner, aesKey);
            } else if (option == 2) {
                retrieveCredentials(scanner, aesKey);
            } else if (option == 3) {
                System.out.println("Exiting the Password Manager.");
                break;
            }
        }
    }
    
    private static SecretKey getKeyFromPassword(String password) throws Exception {
      
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = factory.generateSecret(spec).getEncoded();

        return new SecretKeySpec(key, "AES");
    }

    private static String encrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(data));
        return new String(decryptedBytes);
    }

   
    private static void addNewCredentials(Scanner scanner, SecretKey aesKey) throws Exception {
        System.out.print("Enter the website: ");
        String website = scanner.nextLine();
        System.out.print("Enter your username: ");
        String username = scanner.nextLine();
        System.out.print("Enter your password: ");
        String password = scanner.nextLine();

 
        String encryptedPassword = encrypt(password, aesKey);

 
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("credentials.txt", true))) {
            writer.write(website + "," + username + "," + encryptedPassword);
            writer.newLine();
        }

        System.out.println("Credentials saved successfully.");
    }


    private static void retrieveCredentials(Scanner scanner, SecretKey aesKey) throws Exception {
        System.out.print("Enter the website to retrieve credentials: ");
        String website = scanner.nextLine();

        try (BufferedReader reader = new BufferedReader(new FileReader("credentials.txt"))) {
            String line;
            boolean found = false;
            while ((line = reader.readLine()) != null) {
                String[] credentials = line.split(",");
                if (credentials[0].equals(website)) {
                    String decryptedPassword = decrypt(credentials[2], aesKey);
                    System.out.println("Website: " + credentials[0]);
                    System.out.println("Username: " + credentials[1]);
                    System.out.println("Password: " + decryptedPassword);
                    found = true;
                    break;
                }
            }
            if (!found) {
                System.out.println("No credentials found for this website.");
            }
        } catch (IOException e) {
            System.out.println("Error reading the credentials file.");
        }
    }
}
