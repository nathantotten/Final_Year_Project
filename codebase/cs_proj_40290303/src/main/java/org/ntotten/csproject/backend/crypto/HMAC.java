/*
 * Copyright (c) 2024.
 * Nathan Totten - 40290303 - SSE Final Year Project
 */

package org.ntotten.csproject.backend.crypto;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.SecretKey;
public class HMAC {
    // Using BouncyCastle
    public static byte[] hMacSHA256(String data, SecretKey key)
    {
        long hmacStartTime = System.nanoTime();

        HMac hMac = new HMac(new SHA256Digest());
        hMac.init(new KeyParameter(key.getEncoded()));

        byte[] hmacInput = data.getBytes();
        hMac.update(hmacInput, 0, hmacInput.length);

        byte[] hmacOutput = new byte[hMac.getMacSize()];
        hMac.doFinal(hmacOutput, 0);
        long hmacEndTime = System.nanoTime();

        double elapsed = (hmacEndTime - hmacStartTime) / 1000000.0;
        return hmacOutput;
    }
}
