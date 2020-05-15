package com.example.jwtbasesm2.sm3;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.security.Security;
import java.util.Arrays;

/**
 * @Author swh
 * @Date 2020/5/14 7:54 下午
 **/
public class SM3Util {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static byte[] hash(byte[] srcData) {
        SM3Digest digest = new SM3Digest();
        digest.update(srcData, 0, srcData.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }

    public static boolean verify(byte[] srcData, byte[] sm3Hash) {
        byte[] newHash = hash(srcData);
        if (Arrays.equals(newHash, sm3Hash)) {
            return true;
        } else {
            return false;
        }
    }

    public static void main(String[] args) {
        String message = "abc";
        byte[] res = hash(message.getBytes());
        System.out.println(res.length);
        System.out.println(Hex.toHexString(res));
    }
}
