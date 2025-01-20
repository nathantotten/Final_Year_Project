/*
 * Copyright (c) 2024.
 * Nathan Totten - 40290303 - SSE Final Year Project
 */

package org.ntotten.csproject.backend.test;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.ntotten.csproject.backend.crypto.Encryption;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionTest {

    @BeforeAll
    static void setUp() {
        Encryption.generateKeys();
    }

    @Test
    void keyGen_ReturnsTrue_KeysAreNotNull() {
        // Given an expected successful key generation sequence
        boolean expected = true;
        // When keyGen() is called
        boolean actual = Encryption.generateKeys();
        // Then assert that no error is thrown - keyGen() returns true
        assertEquals(expected, actual);
        assertNotNull(Encryption.getOwnerKey());
        assertNotNull(Encryption.getMaskKey());
        assertNotNull(Encryption.getServerKey());
        assertNotNull(Encryption.getPrime());
        assertNotNull(Encryption.getSearchIV());
    }

    @Test
    void test_getK_m() {
        // Given keys have been generated in setup
        // When I try to get the master key
        SecretKey k_m = Encryption.getOwnerKey();
        // Then the system returns a SecretKey object
        assertNotNull(k_m);
    }

    @Test
    void test_getK_0() {
        // Given keys have been generated in setup
        // When I try to get the mask key
        SecretKey k_0 = Encryption.getMaskKey();
        // Then the system returns a SecretKey object
        assertNotNull(k_0);
    }

    @Test
    void test_getK_s() {
        // Given keys have been generated in setup
        // When I try to get the session key
        SecretKey k_s = Encryption.getServerKey();
        // Then the system returns a SecretKey object
        assertNotNull(k_s);
    }

    @Test
    void test_getPrime() {
        // Given keys have been generated in setup
        // When I try to get the probabilistic prime number
        BigInteger prime = Encryption.getPrime();
        // Then the system returns a large random prime
        assertNotNull(prime);
    }



    @Test
    void encryptString_GeneratesNonNullCipher() throws Exception {
        // Given a string to encrypt
        String plainText = "Nathan";
        // When I encrypt that string
        Encryption.generateKeys();
        byte[] cipherText = Encryption.encryptString(plainText, Encryption.getOwnerKey(), Encryption.generateInitialisationVector());
        // Then an encrypted byte[] is generated
        assertNotNull(cipherText);
    }

    @Test
    void decryptString_ReturnsExpectedPlaintextForGivenCipher() throws Exception {
        // Given a known plaintext string and corresponding ciphertext
        Encryption.generateKeys();
        SecretKey k_m = Encryption.getOwnerKey();
        String expectedPlaintext = "Nathan";
        byte[] cipher = Encryption.encryptString(expectedPlaintext, k_m, Encryption.generateInitialisationVector());
        // When I decrypt the ciphertext
        String actualPlaintext = new String(Encryption.decryptString(cipher, k_m), StandardCharsets.UTF_8);
        // Then it must match the plaintext
        assertDoesNotThrow(() -> {});
        assertEquals(expectedPlaintext, actualPlaintext);
    }
}