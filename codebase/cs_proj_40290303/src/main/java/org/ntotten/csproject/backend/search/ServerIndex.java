
/*
 * Copyright (c) 2024.
 * Nathan Totten - 40290303 - SSE Final Year Project
 */

package org.ntotten.csproject.backend.search;

import org.ntotten.csproject.backend.documentutil.DocumentUtility;
import org.ntotten.csproject.backend.crypto.Encryption;
import org.ntotten.csproject.backend.crypto.HMAC;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class ServerIndex {

    private static final ArrayList<BigInteger> I_row = new ArrayList<>();     // Row index - stores encrypted file identifiers using AES-256 encryption.
    private static final ArrayList<BigInteger> I_column = new ArrayList<>();     // Column index - stores ci values (inverse modulo of hashed keywords).
    private static BigInteger[][] ServerIndex;   // Server Index Table - stores secure values corresponding to unique instances of words occurring in each document using hash chaining.

    // In a real world cloud deployed application, the product of this buildIndex() would be supplied to the server. The calculation takes place on the user end for security.
    public static void buildIndex() throws NoSuchAlgorithmException {

        HashMap<byte[], HashSet<String>> filesAndWordsSet = DocumentUtility.getMapOfFilesToWordSets();

        if (filesAndWordsSet.isEmpty()) {
            System.err.println("Error building secure index - Document collection is empty!");
            return;
        }

        if (Encryption.getPrime() == null) {
            System.err.println("Error retrieving the large prime number.");
            return;
        }

        BigInteger prime = Encryption.getPrime();

        if (Encryption.getOwnerKey() == null || Encryption.getMaskKey() == null) {
            System.err.println("Error retrieving necessary encryption keys.");
            return;
        }

        SecretKey owner_key = Encryption.getOwnerKey();
        SecretKey mask_key = Encryption.getMaskKey();

        HashSet<String> uniqueWordCollection = DocumentUtility.getAllUniqueWords();

        // Building I_r
        // Iterates over strings in broader unique word set and sets client index to inverse modulo of word HMAC using master key.
        for (String word : uniqueWordCollection) {
            byte[] clientIndex = HMAC.hMacSHA256(word, owner_key);
            BigInteger clientIndexBigInt = new BigInteger(clientIndex);
            BigInteger modInverseCi = clientIndexBigInt.modInverse(prime);
            modInverseCi = modInverseCi.mod(prime);
            I_row.add(modInverseCi);
        }

        // Building I_c
        // Iterates over the file identifiers and stores the encrypted file ID in the column I_c
        for (byte[] encryptedFileName : filesAndWordsSet.keySet()) {
            BigInteger encryptedFileIDBigInt = new BigInteger(encryptedFileName); // Search result will return this encrypted fileID to allow retrieval of correct document.
            I_column.add(encryptedFileIDBigInt);
        }

        // Initialise SI 2D array.
        ServerIndex = new BigInteger[I_column.size()][I_row.size()];

        // Could do column-wise or row-wise operation.
        // Column-wise would iterate over unique words. For each word, iterate over files, check if word is present and do something.
        // Row-wise would iterate over each file, for each file, iterate over the unique words and if the word is present, do something.\
        // NOTE: I only need to read as far into the file as the first appearance of a key word!

        long start = System.nanoTime();
        int rowPointer = 0;
        for (Map.Entry<byte[], HashSet<String>> fileEntry : filesAndWordsSet.entrySet()) {
            int columnPointer = 0;
            for (String uniqueWord : uniqueWordCollection) {
                if (fileEntry.getValue().contains(uniqueWord)) {
                    ServerIndex[rowPointer][columnPointer] = calculateSecureCellValue(uniqueWord, owner_key, mask_key, prime); // Convert to BigInteger;
                } else {
                    BigInteger bigRandomInt = BigInteger.valueOf(SecureRandom.getInstanceStrong().nextInt()).mod(prime);
                    String random = new String(bigRandomInt.toByteArray());
                    ServerIndex[rowPointer][columnPointer] = calculateSecureCellValue(random, owner_key, mask_key, prime);
                }
                columnPointer++;
            }
            rowPointer++;
        }
        long end = System.nanoTime();
        double buildIndexTime = (end - start) / 1000000.0;
        System.out.println("Secure Index Generation Time : " + buildIndexTime + " ms.\n");
    }

    private static BigInteger calculateSecureCellValue(String word, SecretKey owner_key, SecretKey mask_key, BigInteger prime) {
        byte[] encryptedBytes = Encryption.encryptString(word, owner_key, Encryption.getSearchIV()); // Encrypt with data owner key
        BigInteger bigIntEncrypted = new BigInteger(encryptedBytes).mod(prime);

        byte[] hashedWord = HMAC.hMacSHA256(word, mask_key); // Hash with mask key
        BigInteger bigIntHash = new BigInteger(hashedWord).mod(prime);

        BigInteger secureSum = bigIntHash.add(bigIntEncrypted);
        return secureSum.mod(prime);
    }

    public static BigInteger[][] getServerIndex() {
        return ServerIndex;
    }
    public static ArrayList<BigInteger> getI_row() {
        return I_row;
    }
    public static ArrayList<BigInteger> getI_column() {
        return I_column;
    }
}
