/*
 * Copyright (c) 2024.
 * Nathan Totten - 40290303 - SSE Final Year Project
 */

package org.ntotten.csproject.backend.search;

import org.ntotten.csproject.backend.crypto.Encryption;
import org.ntotten.csproject.backend.crypto.HMAC;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

public class Search {
    // Set up a fixed thread pool to execute the callables later.
    private static final ExecutorService executor = Executors.newFixedThreadPool(4);

    // NOTE : This doesn't net the performance benefits I was hoping for - added complexity almost makes it more harm than good.
    public static ArrayList<BigInteger> multiThreadSearch(String keyWord) {
        if (keyWord.isEmpty()) {
            System.err.println("Invalid search: key word is null or empty!");
            return null;
        }

        BigInteger[][] serverIndex = ServerIndex.getServerIndex();
        SecretKey server_key = Encryption.getServerKey();
        BigInteger prime = Encryption.getPrime();
        ArrayList<BigInteger> I_r = ServerIndex.getI_row();
        ArrayList<BigInteger> I_c = ServerIndex.getI_column();

        BigInteger[] trapdoors = Trapdoor.generateTrapdoors(keyWord, server_key);
        BigInteger trapdoor_1 = trapdoors[0];
        BigInteger trapdoor_2 = trapdoors[1];
        BigInteger trapdoor_3 = trapdoors[2];

        // Return value
        ArrayList<BigInteger> encryptedFileNames = new ArrayList<>();
        int size = I_r.size();

        List<Future<SearchResult>> futures = new ArrayList<>();

        // When we do the comparison to check which column to search over (which j for I_r[j] do we want to focus on)
        // We will loop over the values in I_r[] and run this comparison on each:
        // It foes as follows: if ( t_1 == HMAC_ks([e + msk + I_r[j]^-1] (mod prime) ) ) then set int column ptr as j.

        long searchIrStart = System.nanoTime();
        for (int i = 0; i < 4; i++) {
            // Determine start and end pointers for each thread
            final int start = i * (size / 4);
            final int end = (i == 3) ? size : (start + size / 4);
            Callable<SearchResult> task = () -> {
                // For each word in I_r[] within this thread's chunk
                for (int colPtr = start; colPtr < end; colPtr++) {

                    BigInteger valueAtIndexJ = I_r.get(colPtr);

                    // Calculate e and msk
                    // e = t_2 x I_r[j] (mod prime)
                    BigInteger e = trapdoor_2.multiply(valueAtIndexJ).mod(prime);

                    // msk = (t_3 x e^-1(mod prime)) (mod prime)
                    BigInteger inverseModE = e.modInverse(prime);
                    BigInteger msk = trapdoor_3.multiply(inverseModE).mod(prime);

                    // Find modular inverse of I_r[j] => (I_r[j]^-1)(mod prime)
                    BigInteger modularInverseIrJ = valueAtIndexJ.modInverse(prime);

                    // Sum: e + msk + modInverseIrJ (mod prime)
                    BigInteger sumValues = e.add(msk).add(modularInverseIrJ).mod(prime);

                    // Convert to String so that HMAC can be calculated
                    byte[] sumBytes = sumValues.toByteArray();
                    String sumString = new String(sumBytes);

                    // HMAC it with the server key
                    BigInteger resultBigInt = new BigInteger(HMAC.hMacSHA256(sumString, server_key)).mod(prime);

                    // If a match for the keyword is found in I_r
                    if (resultBigInt.equals(trapdoor_1)) {
                        return new SearchResult(colPtr, e, msk);
                    }
                }
                // No match in I_r for keyword - return colPtr = -1.
                return new SearchResult(-1, null, null);
            };
            futures.add(executor.submit(task));
        }

        int columnPointer = -1;
        BigInteger e = null;
        BigInteger msk = null;

        for (Future<SearchResult> future : futures) {
            try {
                SearchResult result = future.get();
                if (result.columnPointer != -1) {
                    columnPointer = result.columnPointer;
                    e = result.e;
                    msk = result.msk;
                    break; // match found
                }
            } catch (InterruptedException | ExecutionException ex) {
                ex.printStackTrace();
            }
        }

        executor.shutdown(); // Kill the threads when we know a match is sorted.

        long searchIrEnd = System.nanoTime();
        double searchIrTimeMS = (searchIrEnd - searchIrStart) / 1000000.0;
        System.err.println("Time to search through I_r for keyword: " + searchIrTimeMS + " ms");

        if (columnPointer == -1) {
            System.err.println("Keyword not present!");
            return encryptedFileNames;
        }

        // When we do the comparison that checks if a value at SI[i][j] is present/matching
        //  It goes as follows: if ( [e + msk](mod prime) == I[i][col] ) then add I_c[i] to the list of encrypted file pointers to be returned.
        size = I_c.size();


        long searchOverFilesStart = System.nanoTime();

        for (int i = 0; i < size; i++) {
            assert e != null : "e value is null!";
            assert msk != null : "mask value is null!";

            BigInteger sum = e.mod(prime).add(msk).mod(prime);
            BigInteger valueToCheck = serverIndex[i][columnPointer];

            if (sum.equals(valueToCheck)) {
                encryptedFileNames.add(I_c.get(i));
            }
        }

        long searchOverFilesEnd = System.nanoTime();
        double searchTimeMS = (searchOverFilesEnd - searchOverFilesStart) / 1000000.0;
        //System.err.println("Time to search over files for keyword: " + searchTimeMS + " ms");

        if (encryptedFileNames.isEmpty()) {
            System.err.println("No matching files found :( ");
        } else {
            System.out.println("Search successful! :) ");
        }
        return encryptedFileNames;
    }

    public static ArrayList<BigInteger> search(String keyWord) {

        if (keyWord.isEmpty()) {
            System.err.println("Invalid search : key word is null or empty!");
            return null;
        }

        BigInteger[][] serverIndex = ServerIndex.getServerIndex();
        SecretKey server_key = Encryption.getServerKey();
        BigInteger prime = Encryption.getPrime();
        ArrayList<BigInteger> I_r = ServerIndex.getI_row();
        ArrayList<BigInteger> I_c = ServerIndex.getI_column();

        BigInteger[] trapdoors = Trapdoor.generateTrapdoors(keyWord, server_key);
        BigInteger trapdoor_1 = trapdoors[0];
        BigInteger trapdoor_2 = trapdoors[1];
        BigInteger trapdoor_3 = trapdoors[2];

        // Return value
        ArrayList<BigInteger> encryptedFileNames = new ArrayList<>();

        // When we do the comparison to check which column to search over (which j for I_r[j] do we want to focus on)
        // We will loop over the values in I_r[] and run this comparison on each:
        // It foes as follows: if ( t_1 == HMAC_ks([e + msk + I_r[j]^-1] (mod prime) ) ) then set int column ptr as j.

        BigInteger e = null;
        BigInteger msk = null;
        int columnPointer = 0;
        int size = I_r.size();
        boolean keywordExistsInIR = false;

        long searchIrStart = System.nanoTime();
        // For each word in I_r[]
        for (int j = 0; j < size; j++) {
            BigInteger valueAtIndexJ = I_r.get(j);

            // Calculate e and msk
            // e = t_2 x I_r[j] (mod prime)
            e = trapdoor_2.multiply(valueAtIndexJ);
            e = e.mod(prime);

            // msk = (t_3 x e^-1(mod prime)) (mod prime)
            BigInteger inverseModE = e.modInverse(prime).mod(prime);
            msk = trapdoor_3.multiply(inverseModE);
            msk = msk.mod(prime);

            // Find modular inverse of I_r[j] => (I_r[j]^-1)(mod prime)
            BigInteger modularInverseIrJ = valueAtIndexJ.modInverse(prime);
            modularInverseIrJ = modularInverseIrJ.mod(prime);

            // Sum: e + msk + modInverseIrJ (mod prime)
            BigInteger sumValues = (e.add(msk).add(modularInverseIrJ));
            sumValues = sumValues.mod(prime);

            // Convert result of (e + msk + I_r[j]^-1) to String
            byte[] sumBytes = sumValues.toByteArray();
            String sumString = new String(sumBytes);

            // HMAC with server key
            BigInteger resultBigInt = new BigInteger(HMAC.hMacSHA256(sumString, server_key)).mod(prime);

            // Check if the values are equal - if yes, save the pointer we are at and break out.
            if (resultBigInt.equals(trapdoor_1)) {
                //System.out.println("Match for keyword found at position: " + j);
                columnPointer = j;
                keywordExistsInIR = true;
                break;
            }
            // This loop appears to be doing its job!
        }
        long searchIrEnd = System.nanoTime();
        double searchIrTimeMS = (searchIrEnd - searchIrStart) / 1000000.0;
        //System.err.println("Time to search through I_r for keyword: " + searchIrTimeMS + " ms");

        if (!keywordExistsInIR) {
            System.err.println("Search Complete - No matches found :(");
            return encryptedFileNames;
        }

        // When we do the comparison that checks if a value at SI[i][j] is present/matching
        //  It goes as follows: if ( [e + msk](mod prime) == I[i][col] ) then add I_c[i] to the list of encrypted file pointers to be returned.
        size = I_c.size();


        long searchOverFilesStart = System.nanoTime();

        for (int i = 0; i < size; i++) {
            assert e != null : "e value is null!";
            assert msk != null : "mask value is null!";

            //System.out.println("col pointer: " + columnPointer);

            BigInteger sum = e.mod(prime).add(msk).mod(prime);
            //System.out.println("sum: " + sum);
            BigInteger valueToCheck = serverIndex[i][columnPointer];
            //System.out.println("value to check: " + valueToCheck);

            if (sum.equals(valueToCheck)) {
                //System.out.println("Match found at position: SI[" + i + "][" + columnPointer + "]");
                encryptedFileNames.add(I_c.get(i));
            }
        }

        long searchOverFilesEnd = System.nanoTime();
        double searchTimeMS = (searchOverFilesEnd - searchOverFilesStart) / 1000000.0;
        System.err.println("Time to search over files for keyword: " + searchTimeMS + " ms");

        if (encryptedFileNames.isEmpty()) {
            System.err.println("No matching files found :( ");
        } else {
            System.out.println("Search successful! :) ");
        }
        return encryptedFileNames;
    }

    // Private class to make it easier to grab the values of e and msk once a match is found in I_r.
    private static class SearchResult {
        int columnPointer;
        BigInteger e;
        BigInteger msk;

        public SearchResult(int columnPointer, BigInteger e, BigInteger msk) {
            this.columnPointer = columnPointer;
            this.e = e;
            this.msk = msk;
        }
    }
}


