package com.example.jwtbasesm2.sm2;

import org.bouncycastle.crypto.signers.DSAEncoding;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.Arrays;


public class SM2SignResult {
    private BigInteger signR;
    private BigInteger signS;

    public SM2SignResult() {
    }

    public SM2SignResult(BigInteger signR, BigInteger signS) {
        this.signR = signR;
        this.signS = signS;
    }

    public SM2SignResult(String sign) {
        int index = sign.indexOf("|");
        if(index <= 0){
            throw new RuntimeException("signature is not right");
        }
        String sr = sign.substring(0,index);
        String ss = sign.substring(index+1,sign.length());
        this.signR = new BigInteger(sr,16);
        this.signS = new BigInteger(ss,16);
    }

    public BigInteger getSignR() {
        return signR;
    }

    public BigInteger getSignS() {
        return signS;
    }

    @Override
    public String toString() {
     return signR.toString(16)+"|"+signS.toString(16);
    }

    public byte[] encodeStandardDSA() throws Exception {
        return encode(StandardDSAEncoding.INSTANCE);
    }

    public byte[] encodePlainDSA() throws Exception{
        return encode(PlainDSAEncoding.INSTANCE);
    }

    public void decodeStandardDSA(byte[] signDSAEncoding) throws Exception{
        decode(StandardDSAEncoding.INSTANCE, signDSAEncoding);
    }

    public void decodePlainDSA(byte[] signDSAEncoding) throws Exception{
        decode(PlainDSAEncoding.INSTANCE, signDSAEncoding);
    }

    private byte[] encode(DSAEncoding dsaEncoding) throws Exception {
       // BigInteger bigIntegerSignR = new BigInteger(Hex.toHexString(getSignR()), 16);
        //BigInteger bigIntegerSignS = new BigInteger(Hex.toHexString(getSignS()), 16);
        return dsaEncoding.encode(SM2Constants.SM2_ECC_N, signR, signS);
    }

    private void decode(DSAEncoding dsaEncoding, byte[] signDSAEncoding) throws Exception{
        BigInteger[] bigIntegers = dsaEncoding.decode(SM2Constants.SM2_ECC_N, signDSAEncoding);
        this.signR = bigIntegers[0];
        this.signS = bigIntegers[1];
    }
}
