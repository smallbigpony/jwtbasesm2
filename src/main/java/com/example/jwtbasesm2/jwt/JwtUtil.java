package com.example.jwtbasesm2.jwt;

import io.jsonwebtoken.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

/**
 * @Author: swh
 * @Date: 2020 04 2020/4/1 14:48
 * @Version: 1.0
 */
public class JwtUtil {
    //有效期为
    public static final Long JWT_TTL = 3600000L;// 60 * 60 *1000  一个小时
    //设置秘钥明文
    public static final String JWT_KEY = "itcast";

    /**
     * 创建未使用签名算法的jwt
     * @param id jwt的唯一标识
     * @param subject json数据
     * @param iss 签发者
     * @param nbfDate 定义在什么时间之前，该jwt都是不可用的.
     * @param ttlMillis 超时时间
     * @return jwt字符串
     */
    public static String createJWT(String id, String subject,String iss, Date nbfDate,Long ttlMillis) {
        //定义jwt签名的算法
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.NONE;
        //将当前时间+超时时间
        if(ttlMillis==null){
            ttlMillis=JwtUtil.JWT_TTL;
        }
        Date nowDate = new Date(System.currentTimeMillis());
        long expMillis = nowDate.getTime() + ttlMillis;
        //将时间定义为date类型
        Date expDate = new Date(expMillis);
        //获取签名时候使用的密钥
        SecretKey secretKey = generalKey();

        JwtBuilder builder = Jwts.builder()
                .setId(id)              //唯一的ID
                .setSubject(subject)   // 主题  可以是JSON数据
                .setIssuer(iss)     // 签发者
                .setIssuedAt(nowDate)// 签发时间
                .setNotBefore(nbfDate)
                //.signWith(signatureAlgorithm, secretKey) //使用HS256对称加密算法签名, 第二个参数为秘钥
                .setExpiration(expDate);// 设置过期时间
        return builder.compact();
    }

    /**
     * 生成加密后的秘钥 secretKey
     * @return
     */
    public static SecretKey generalKey() {
        byte[] encodedKey = Base64.getDecoder().decode(JwtUtil.JWT_KEY);
        SecretKey key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
        return key;
    }
    public static Claims parseJWT(String jwt) throws Exception {
        SecretKey key = generalKey();  //签名秘钥，和生成的签名的秘钥一模一样
        Claims claims = Jwts.parser()  //得到DefaultJwtParser
                //.setSigningKey(key)                 //设置签名的秘钥
                .parseClaimsJws(jwt).getBody();     //设置需要解析的jwt
        return claims;
    }

    public static void main(String[] args) throws Exception {
       /* String jwt = createJWT("swh", "8888", 60*60*1000L);
        System.out.println(jwt);
        String ss = "song";
        System.out.println(new String(Base64.getEncoder().encode(ss.getBytes())));
        System.out.println(new String(Base64.getDecoder().decode("eyJhbGciOiJIUzI1NiJ9".getBytes())));*/
       Long now = System.currentTimeMillis();
       Date nowDate = new Date(now);
       System.out.println(now);
       System.out.println(nowDate.getTime());
        /*Thread.sleep(10L);
        try {
            Claims claims = parseJWT(jwt);
            System.out.println(claims.getId());
            System.out.println(claims.getSubject());
        } catch (UnsupportedJwtException e) {
          System.out.println(e.toString());
        } catch (ExpiredJwtException e) {
            throw new RuntimeException("过期",e);
        }*/
    }
}
