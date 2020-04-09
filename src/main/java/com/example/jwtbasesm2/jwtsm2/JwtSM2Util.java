package com.example.jwtbasesm2.jwtsm2;

import com.example.jwtbasesm2.jwt.JwtUtil;
import com.example.jwtbasesm2.sm2.SM2Helper;
import com.example.jwtbasesm2.sm2.SM2KeyHelper;
import com.example.jwtbasesm2.sm2.SM2KeyPair;
import com.example.jwtbasesm2.sm2.SM2SignResult;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.impl.TextCodec;
import io.jsonwebtoken.lang.Strings;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.swing.plaf.synth.SynthScrollBarUI;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

/**
 * @Author: swh
 * @Date: 2020 04 2020/4/7 13:52
 * @Version: 1.0
 */
public class JwtSM2Util {

    private static ObjectMapper objectMapper = new ObjectMapper();
    private static final String ISO_8601_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";

    /**
     * 将jwtheader中的none替换为sm2，返回head+.+payload
     *
     * @param jwtEncodeByBase64
     * @return
     */
    public static String changeOriginalJwt(String jwtEncodeByBase64) {
        String base64UrlEncodedHeader = null;
        String base64UrlEncodedPayload = null;
        String base64UrlEncodedDigest = null;
        int index = jwtEncodeByBase64.indexOf(".");
        base64UrlEncodedHeader = jwtEncodeByBase64.substring(0, index);
        jwtEncodeByBase64 = jwtEncodeByBase64.substring(index + 1, jwtEncodeByBase64.length());
        index = jwtEncodeByBase64.indexOf(".");
        base64UrlEncodedPayload = jwtEncodeByBase64.substring(0, index);
        //System.out.println(base64UrlEncodedHeader);
        //System.out.println(base64UrlEncodedPayload);
        String header = TextCodec.BASE64URL.decodeToString(base64UrlEncodedHeader);
        header = header.replaceFirst("none", "SM2");
        //System.out.println(header);
        base64UrlEncodedHeader = TextCodec.BASE64URL.encode(header);
        //System.out.println(base64UrlEncodedHeader);
        return base64UrlEncodedHeader + "." + base64UrlEncodedPayload;
    }

    /**
     * 创建使用SM2签名算法的jwt
     *
     * @param id         jwt唯一标识，也用做SM2签名算法中的用户可辨别标识(IDA)
     * @param sub
     * @param iss
     * @param nbfDate    定义在什么时间之前，该jwt都是不可用的.
     * @param ttlMillis
     * @param sm2KeyPair
     * @return
     */
    public static String creatSM2Jwt(String id, String sub, String iss, Date nbfDate, Long ttlMillis, SM2KeyPair sm2KeyPair) throws Exception {
        String jwtBaseNone = JwtUtil.createJWT(id, sub, iss, nbfDate, ttlMillis);
        String base64UrlEncodeHeaderPayload = changeOriginalJwt(jwtBaseNone);
        String signature = SM2Helper.sign(base64UrlEncodeHeaderPayload.getBytes(), SM2KeyHelper.buildECPrivateKeyParameters(sm2KeyPair.getPrivateKey()), id.getBytes()).toString();
        return base64UrlEncodeHeaderPayload + "." + signature;
    }

    /**
     * 解析 jwt
     *
     * @param jwt
     * @param sm2KeyPair
     * @param id         jwt唯一标识，也用做SM2签名算法中的用户可辨别标识(IDA)
     * @return
     */
    public static Claims parse(String jwt, SM2KeyPair sm2KeyPair, String id) throws Exception {
        String base64UrlEncodedHeader = null;
        String base64UrlEncodedPayload = null;
        String base64UrlEncodedDigest = null;
        Claims claims = null;
        int delimiterCount = 0;
        StringBuilder sb = new StringBuilder(128);
        char[] arr$ = jwt.toCharArray();
        int len$ = arr$.length;

        for (int i$ = 0; i$ < len$; ++i$) {
            char c = arr$[i$];
            if (c == '.') {
                CharSequence tokenSeq = Strings.clean(sb);
                String token = tokenSeq != null ? tokenSeq.toString() : null;
                if (delimiterCount == 0) {
                    base64UrlEncodedHeader = token;
                } else if (delimiterCount == 1) {
                    base64UrlEncodedPayload = token;
                }

                ++delimiterCount;
                sb.setLength(0);
            } else {
                sb.append(c);
            }
        }
        if (delimiterCount != 2) {
            String msg = "JWT strings must contain exactly 2 period characters. Found: " + delimiterCount;
            throw new MalformedJwtException(msg);
        }
        if (sb.length() > 0) {
            base64UrlEncodedDigest = sb.toString();
        } else {
            throw new RuntimeException("jwt signature can not be null");
        }
        SM2SignResult sm2SignResult = new SM2SignResult(base64UrlEncodedDigest);
        String input = base64UrlEncodedHeader + "." + base64UrlEncodedPayload;
        if (!SM2Helper.verifySign(input.getBytes(), sm2SignResult, SM2KeyHelper.buildECPublicKeyParameters(sm2KeyPair), id.getBytes())) {
            throw new RuntimeException("Signature verification error");
        }
        String payload = TextCodec.BASE64URL.decodeToString(base64UrlEncodedPayload);
        if (payload.charAt(0) == '{' && payload.charAt(payload.length() - 1) == '}') {
            Map<String, Object> claimsMap = readValue(payload);
            claims = new DefaultClaims(claimsMap);
        } else {
            throw new RuntimeException("payload format is not right");
        }
        SimpleDateFormat sdf;
        Date now = new Date(System.currentTimeMillis());
        Date nbf = claims.getNotBefore();
        Date exp = claims.getExpiration();
        //token MUST NOT be accepted on or after any specified exp time:
        if (exp != null && now.after(exp)) {
            sdf = new SimpleDateFormat(ISO_8601_FORMAT);
            String expVal = sdf.format(exp);
            String nowVal = sdf.format(now);

            long differenceMillis = now.getTime() - exp.getTime();

            String msg = "JWT expired at " + expVal + ". Current time: " + nowVal + ", a difference of " +
                    differenceMillis + " milliseconds.";
            throw new RuntimeException(msg);
        }
        //token MUST NOT be accepted before any specified nbf time:
        if (nbf != null && now.before(nbf)) {
            sdf = new SimpleDateFormat(ISO_8601_FORMAT);
            String nbfVal = sdf.format(nbf);
            String nowVal = sdf.format(now);

            long differenceMillis = nbf.getTime() - now.getTime();

            String msg = "JWT must not be accepted before " + nbfVal + ". Current time: " + nowVal +
                    ", a difference of " +
                    differenceMillis + " milliseconds.";
            throw new RuntimeException(msg);
        }
        return claims;


    }

    private static Map<String, Object> readValue(String val) {
        try {
            return (Map) objectMapper.readValue(val, Map.class);
        } catch (IOException var3) {
            throw new MalformedJwtException("Unable to read JSON value: " + val, var3);
        }
    }

    public static void main(String[] args) throws Exception {
        String id = "sjd_aac-asd";
        String sub = "{\"name\":\"huge\",\"telNumber\":\"18852178961\",\"address\":\"Changchun JinLin\"}";
        String iss = "jlu_swh";
        Date nbfDate = new Date(System.currentTimeMillis());
        Long ttlMillis = 60 * 60 * 1000L; // 一小时
        SM2KeyPair sm2KeyPair = SM2KeyHelper.generateKeyPair();

        //生成jwt
        String jwt = creatSM2Jwt(id,sub,iss,nbfDate,ttlMillis,sm2KeyPair);
        System.out.println(jwt);

        //验证jwt
        Claims claims = parse(jwt,sm2KeyPair,id);
        System.out.println("sub:" + claims.getSubject());
        //更改jwt的一个字母，尝试验证
        //String jwt_1 = "a"+jwt;
        //Claims claims_1 = parse(jwt_1,sm2KeyPair,id);

        //验证nbf
        /*Date nbfDate_1 = new Date(System.currentTimeMillis()+60 * 30 * 1000L);
        Date now = new Date(System.currentTimeMillis());
        SimpleDateFormat sdf = new SimpleDateFormat(ISO_8601_FORMAT);
        System.out.println(sdf.format(nbfDate_1));
        System.out.println(sdf.format(now));
        System.out.println(now.before(nbfDate_1));
        String jwt_1 = creatSM2Jwt(id,sub,iss,nbfDate_1,ttlMillis,sm2KeyPair);
        Claims claims_1 = parse(jwt_1,sm2KeyPair,id);
        System.out.println("sub:" + claims_1.getSubject());*/

        //验证exp
       /* Long ttlMillis_1 = 1000*10L;
        String jwt_1 = creatSM2Jwt(id,sub,iss,nbfDate,ttlMillis_1,sm2KeyPair);
        Thread.sleep(1000*12L);
        Claims claims_1 = parse(jwt_1,sm2KeyPair,id);
        System.out.println("sub:" + claims_1.getSubject());*/
    }
}
