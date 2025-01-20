/*
 * Copyright (c) 2024.
 * Nathan Totten - 40290303 - SSE Final Year Project
 */

package org.ntotten.csproject.backend.crypto;

import org.ntotten.csproject.backend.shell.ShellHelper;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Encryption {
    private static final String ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256;
    private static final int TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    // Random prime.
    private static BigInteger prime;
    // Master key for user/data owner. Used to decrypt plaintext data.
    private static SecretKey owner_key;
    // Mask key for use with secure index table. Hashing to apply mask.
    private static SecretKey mask_key;
    // Session key that will be exposed to the server. Cannot be used to decrypt the data.
    private static SecretKey server_key;
    private static byte[] searchIV;

    private static final String[] keyAliases = {"data-owner-secret", "mask-secret", "session-secret", "prime", "search-iv"};

    public static SecretKey getOwnerKey() {
        return owner_key;
    }
    private static void setOwnerKey(SecretKey new_owner_key) {
        owner_key = new_owner_key;
    }

    public static SecretKey getMaskKey() {
        return mask_key;
    }
    private static void setMaskKey(SecretKey new_mask_key) {
        mask_key = new_mask_key;
    }

    public static SecretKey getServerKey() {
        return server_key;
    }
    private static void setServerKey(SecretKey new_server_key) {
        server_key = new_server_key;
    }

    public static BigInteger getPrime() {
        return prime;
    }
    private static void setPrime(BigInteger newPrime) {
        prime = newPrime;
    }

    public static byte[] getSearchIV() {
        return searchIV;
    }

    private static void setSearchIV(byte[] newSearchIV) {
        searchIV = newSearchIV;
    }

    public static boolean checkKeys(ShellHelper shellHelper) {
        if (
                Encryption.getPrime() == null ||
                        Encryption.getServerKey() == null ||
                        Encryption.getOwnerKey() == null ||
                        Encryption.getMaskKey() == null
        ) {
            // Do I want to stop the user and tell them they have not provided keys?
            shellHelper.printWarning("Encryption keys could not be found! Please generate encryption keys first.");
            return false;
        } else {
            return true;
        }
    }

    // All key generation and encryption takes place - in isolation - on the user's end to minimise the amount of data the server sees.
    public static boolean generateKeys() {
        // Tell user what is happening.
        try {
            long keyGenStart = System.nanoTime();

            // Setup Key generator.
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(KEY_SIZE, SecureRandom.getInstanceStrong());

            // Create the keys we need.
            // Master Key
            owner_key = keyGen.generateKey();
            // Mask Key
            mask_key = keyGen.generateKey();
            // Session/Server Key
            server_key = keyGen.generateKey();
            // Create a random prime number using probabilistic prime number generator.
            prime = BigInteger.probablePrime(2048, SecureRandom.getInstanceStrong());
            // Create IV that is ONLY used for searching - not for secure encryption of data!
            searchIV = generateInitialisationVector();

            long keyGenEnd = System.nanoTime();
            double elapsedTime = (keyGenEnd - keyGenStart) / 1000000.0;
            System.out.println("KeyGen: Key generation took " + elapsedTime + " ms.\n");
            return true;
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error generating encryption keys!" + e.getMessage());
            return false;
        }
    }

    // Encrypt text with a chosen algorithm, secret key, and initialisation vector.
    public static byte[] encryptString(String plaintext, SecretKey secretKey, byte[] IV)
    {
        try {
            return cryptoOperation(plaintext.getBytes(UTF_8), secretKey, Cipher.ENCRYPT_MODE, IV);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] decryptString(byte[] ciphertext, SecretKey secretKey)
            throws Exception
    {
        return cryptoOperation(ciphertext, secretKey, Cipher.DECRYPT_MODE, extractInitialisationVector(ciphertext));
    }

    private static byte[] cryptoOperation(byte[] bytes, SecretKey secretKey, int mode, byte[] IV)
            throws Exception
    {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        byte[] initialisationVector;
        GCMParameterSpec gcmParameterSpec;

        if (mode == Cipher.ENCRYPT_MODE) {
            // Generate IV
            initialisationVector = IV;
            // Init GCM Param Spec using new IV
            gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, initialisationVector);
            // Init cipher using mode, secret key, and new gcm param spec.
            cipher.init(mode, secretKey, gcmParameterSpec);

            // Perform encryption
            byte[] encrypted = cipher.doFinal(bytes);

            // Prepend the IV to the ciphertext
            byte[] combined = new byte[initialisationVector.length + encrypted.length];
            // Copy IV bytes into beginning of combined array.
            System.arraycopy(initialisationVector, 0, combined, 0, initialisationVector.length);
            // Copy encrypted bytes into the rest of the combined array.
            System.arraycopy(encrypted, 0, combined, initialisationVector.length, encrypted.length);

            // Return the combination of IV and ciphertext.
            return combined;

        } else if (mode == Cipher.DECRYPT_MODE) {

            // Extract IV from the beginning of the combined array
            initialisationVector = IV;

            // Extract ciphertext from the rest of the combined array
            byte[] ciphertext = extractCiphertext(bytes);

            // Init GCM param spec using extracted IV
            gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, initialisationVector);
            // Init cipher using relevant params
            cipher.init(mode, secretKey, gcmParameterSpec);

            // Perform decryption
            return cipher.doFinal(ciphertext);
        } else {
            throw new IllegalArgumentException("Invalid mode specified");
        }
    }

    private static byte[] extractInitialisationVector(byte[] combined) {
        byte[] initialisationVector = new byte[Encryption.IV_LENGTH];
        // Copy the IV bytes from combined into the IV array, ready to be used for decrypting ciphertext.
        System.arraycopy(combined, 0, initialisationVector, 0, Encryption.IV_LENGTH);
        return initialisationVector;
    }

    private static byte[] extractCiphertext(byte[] combined) {
        int ciphertextLength = combined.length - IV_LENGTH;
        byte[] ciphertext = new byte[ciphertextLength];
        // Copy only the encrypted bytes from the combined array into the ciphertext array, ready for decryption.
        System.arraycopy(combined, IV_LENGTH, ciphertext, 0, ciphertextLength);
        return ciphertext;
    }

    public static byte[] generateInitialisationVector() throws NoSuchAlgorithmException {
        // Should be length 12 for GCM mode of AES encryption.
        byte[] initialisationVector = new byte[IV_LENGTH];
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        secureRandom.nextBytes(initialisationVector);
        return initialisationVector;
    }

    // https://www.baeldung.com/java-keystore
    public static void exportKeysToKeyStore(char[] keystorePassword)
            throws KeyStoreException,
            NoSuchAlgorithmException,
            IOException,
            CertificateException
    {
        // Convert big Prime to SecretKey
        byte[] primeBytes = prime.toByteArray();
        SecretKey primeToSecretKey = new SecretKeySpec(primeBytes, "AES");

        // Convert searchIV to SecretKey
        SecretKey searchIVToSecretKey = new SecretKeySpec(searchIV, "AES");

        // Initialise KeyStore - PKCS12, NOT JKS as it is deprecated and no longer secure.
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, keystorePassword);

        // Generate SecretKeyEntry instances for each of the keys.
        KeyStore.SecretKeyEntry masterKey = new KeyStore.SecretKeyEntry(owner_key);
        KeyStore.SecretKeyEntry maskKey = new KeyStore.SecretKeyEntry(mask_key);
        KeyStore.SecretKeyEntry sessionKey = new KeyStore.SecretKeyEntry(server_key);
        KeyStore.SecretKeyEntry primeKey = new KeyStore.SecretKeyEntry(primeToSecretKey);
        KeyStore.SecretKeyEntry searchIVKey = new KeyStore.SecretKeyEntry(searchIVToSecretKey);

        // Generate ProtectionParameter with the encoded password.
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(keystorePassword);

        // Add the entries.
        keyStore.setEntry("data-owner-secret", masterKey, protectionParameter);
        keyStore.setEntry("mask-secret", maskKey, protectionParameter);
        keyStore.setEntry("session-secret", sessionKey, protectionParameter);
        keyStore.setEntry("prime", primeKey, protectionParameter);
        keyStore.setEntry("search-iv", searchIVKey, protectionParameter);

        // Export the keystore.
        try (FileOutputStream fileOutputStream = new FileOutputStream("sse_keystore.p12")) {
            System.out.println("Exporting keys to: 'sse_keystore.p12' ");
            keyStore.store(fileOutputStream, keystorePassword);
            System.out.println("Keys exported successfully!");
        } catch (IOException e) {
            System.err.println("Error exporting keys: " + e.getMessage());
        }
    }

    public static void loadKeysFromKeystore(String keystorePath, char[] keystorePassword) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(keystorePath)) {
                keyStore.load(fis, keystorePassword);
            }

            SecretKey[] keys = new SecretKey[keyAliases.length];
            for (int i = 0; i < keyAliases.length; i++) {
                keys[i] = (SecretKey) keyStore.getKey(keyAliases[i], keystorePassword);
            }
            setSecurityParams(keys);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load keys from keystore", e);
        }
    }

    private static void setSecurityParams(SecretKey[] keys) {
        setOwnerKey(keys[0]);
        setMaskKey(keys[1]);
        setServerKey(keys[2]);
        BigInteger newPrime = new BigInteger(keys[3].getEncoded());
        setPrime(newPrime);
        setSearchIV(keys[4].getEncoded());
    }
}
