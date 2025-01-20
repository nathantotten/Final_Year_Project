/*
 * Copyright (c) 2024.
 * Nathan Totten - 40290303 - SSE Final Year Project
 */

package org.ntotten.csproject.backend.test;

import org.bouncycastle.crypto.macs.HMac;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.ntotten.csproject.backend.crypto.HMAC;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class HMACTest {
    SecretKey key;
    String plaintext;

    @Mock
    private HMac mockHMac;


    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256, SecureRandom.getInstanceStrong());
        key = keyGenerator.generateKey();
        plaintext = "Nathan";
    }

    @Test
    void hMacSHA256_ReturnsNonNullHMAC() {
        // Given plaintext and key have been set
        // When I generate a HMAC
        byte[] hmac = HMAC.hMacSHA256(plaintext, key);
        // Then the hmac function returns an appropriate byte[]
        assertNotNull(hmac);
    }

    @Test
    public void hMacSHA256_OutputLengthMatchesKnownGoodImplementation() throws Exception {

        byte[] hmacOutputFromBouncyCastle = HMAC.hMacSHA256(plaintext, key);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key.getEncoded(), "HmacSHA256"));
        byte[] hmacOutputFromJCA = mac.doFinal(plaintext.getBytes());

        // Not comparing actual outputs, but verifying they have the same length
        assertEquals(hmacOutputFromJCA.length, hmacOutputFromBouncyCastle.length);
    }
}