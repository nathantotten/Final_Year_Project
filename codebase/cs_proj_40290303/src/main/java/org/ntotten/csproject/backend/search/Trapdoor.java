/*
 * Copyright (c) 2024.
 * Nathan Totten - 40290303 - SSE Final Year Project
 */

package org.ntotten.csproject.backend.search;

import org.ntotten.csproject.backend.crypto.Encryption;
import org.ntotten.csproject.backend.crypto.HMAC;

import javax.crypto.SecretKey;
import java.math.BigInteger;

public class Trapdoor {

    public static BigInteger[] generateTrapdoors(String searchKeyWord, SecretKey server_key) {

        if (searchKeyWord == null || searchKeyWord.isEmpty()) {
            throw new RuntimeException("Search keyword is null or empty!");
        }

        SecretKey owner_key = Encryption.getOwnerKey();
        SecretKey mask_key = Encryption.getMaskKey();
        BigInteger prime = Encryption.getPrime();

        BigInteger[] trapdoors = new BigInteger[3];

        try {
            long trapdoorGenStart = System.nanoTime();

            // Generate encrypted key word.
            byte[] encryptedBytes = Encryption.encryptString(searchKeyWord, owner_key, Encryption.getSearchIV());
            BigInteger encryptedBigInt = new BigInteger(encryptedBytes);
            encryptedBigInt = encryptedBigInt.mod(prime);

            // Generate mask from key word.
            byte[] maskedKeyWord = HMAC.hMacSHA256(searchKeyWord, mask_key);
            BigInteger maskBigInt = new BigInteger(maskedKeyWord);
            maskBigInt = maskBigInt.mod(prime);

            // Generate client index HMAC.
            byte[] clientIndex = HMAC.hMacSHA256(searchKeyWord, owner_key);
            BigInteger clientIndexBigInt = new BigInteger(clientIndex);
            clientIndexBigInt = clientIndexBigInt.mod(prime);

            // Generate trapdoor 1 using session key and sum of encrypted word, mask, and client index.
            BigInteger sum = (clientIndexBigInt.add(maskBigInt).add(encryptedBigInt)).mod(prime);
            String sumString = new String(sum.toByteArray());
            byte[] trapdoor1ByteArray = HMAC.hMacSHA256(sumString, server_key);
            BigInteger trapdoor1 = new BigInteger(trapdoor1ByteArray);
            trapdoor1 = trapdoor1.mod(prime);

            // Generate trapdoor 2 using product of encrypted word and client index.
            BigInteger trapdoor2 = encryptedBigInt.multiply(clientIndexBigInt);
            trapdoor2 = trapdoor2.mod(prime);

            // Generate trapdoor 3 using product of encrypted word and mask.
            BigInteger trapdoor3 = encryptedBigInt.multiply(maskBigInt);
            trapdoor3 = trapdoor3.mod(prime);

            // Add trapdoors to return array object.
            trapdoors[0] = trapdoor1;
            trapdoors[1] = trapdoor2;
            trapdoors[2] = trapdoor3;

            long trapdoorGenEnd = System.nanoTime();
            System.out.println("Trapdoor generation time: " + (trapdoorGenEnd - trapdoorGenStart) / 1000000.0 + " milliseconds.");

            return trapdoors;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}