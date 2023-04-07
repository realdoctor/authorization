package com.realdoctor.authorization.util;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import com.realdoctor.authorization.JwtConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.Base64Codec;
import io.jsonwebtoken.lang.Assert;

public class JwtUtil {

    public static final String JWT_ID                            = "jwt";
    public static final String JWT_SECRET                        = JwtConfig.JWT_SECRET;
    public static final int    JWT_TOKEN_EXPIRES_SECONDS         = JwtConfig.TOKEN_EXPIRES_SECONDS;
    public static final int    JWT_TOKEN_REFRESH_EXPIRES_SECONDS = JwtConfig.TOKEN_REFRESH_EXPIRES_SECONDS;
    public static final int    JWT_TTL                           = JWT_TOKEN_EXPIRES_SECONDS * 1000; // token有效时间，单位毫秒
    public static final int    JWT_REFRESH_TTL                   = JWT_TOKEN_REFRESH_EXPIRES_SECONDS * 1000;

    /**
     * 签发JWT
     * 
     * @param id jwt的唯一身份标识，主要用来作为一次性token，从而回避重放攻击。
     * @param iss jwt签发者
     * @param subject jwt所面向的用户
     * @param ttlMillis 有效期，单位毫秒
     * @return token
     */
    public static String createJWT(String subject, Map<String, Object> claims, long ttlMillis) {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        // 生成签名密钥，就是一个base64加密后的字符串。
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(JWT_SECRET);
        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());
        // 添加构成JWT的参数
        JwtBuilder builder =
                Jwts.builder().setHeaderParam("typ", "JWT").setId(jwtId()).setIssuedAt(now).setSubject(subject)
                        .setIssuer("realdoctor").signWith(signatureAlgorithm, signingKey);
        if (claims != null && !claims.isEmpty()) {
            for (Map.Entry<String, Object> m : claims.entrySet()) {
                builder.claim(m.getKey(), m.getValue());
            }
        }
        // 添加Token过期时间
        if (ttlMillis >= 0) {
            // 过期时间
            long expMillis = nowMillis + ttlMillis;
            // 现在是什么时间
            Date exp = new Date(expMillis);
            // 系统时间之前的token都是不可以被承认的
            builder.setExpiration(exp).setNotBefore(now);
        }
        // 生成JWT
        return builder.compact();
    }

    /**
     * 解析Token，同时也能验证Token，当验证失败返回null
     * 
     * @param token
     * @return
     */
    public static Claims parseJWT(String token) {
        Assert.notNull(token);
        try {
            Claims claims = Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(JWT_SECRET))
                    .parseClaimsJws(token).getBody();
            return claims;
        } catch (Exception ex) {
            return null;
        }
    }

    public static String deserializeKey(String key) {
        Assert.notNull(key);
        return Base64Codec.BASE64URL.decodeToString(key);
    }

    public static String serializeKey(String key) {
        Assert.notNull(key);
        return Base64Codec.BASE64URL.encode(key.getBytes());
    }

    /**
     * 生成Token
     * 
     * @param subject
     * @return
     */
    public static String generToken(String subject) {
        return JwtUtil.createJWT(subject, null, JwtUtil.JWT_TTL);
    }

    public static String generToken(String subject, Map<String, Object> claims) {
        return JwtUtil.createJWT(subject, claims, JwtUtil.JWT_TTL);
    }

    public static String generRefreshToken(String subject) {
        return JwtUtil.createJWT(subject, null, JwtUtil.JWT_REFRESH_TTL);
    }

    public static String generRefreshToken(String subject, Map<String, Object> claims) {
        return JwtUtil.createJWT(subject, claims, JwtUtil.JWT_REFRESH_TTL);
    }

    /**
     * 判断token是否过期
     * 
     * @param token
     * @return True|有效，false|无效
     */
    public static Boolean isTokenExpired(String token) {
        final Claims claims = JwtUtil.parseJWT(token);
        if (claims != null) {
            final Date expiration = claims.getExpiration();
            if (expiration != null) {
                return expiration.before(new Date());
            }
        }
        return false;
    }

    /**
     * 解析Token
     * 
     * @param token
     * @return subject
     */
    public static Claims parseToken(String token) {
        return JwtUtil.parseJWT(token);
    }
    
    public static Claims getClaimsByToken(String token) {
        return JwtUtil.parseJWT(token);
    }
    
    public static String getSubjectByToken(String token) {
        Claims claims = getClaimsByToken(token);
        if (claims != null) {
            return claims.getSubject();
        }
        return null;
    }
    
    /**
     * 
     */
    public static String[] CHARS = new String[] {"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n",
            "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8",
            "9", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T",
            "U", "V", "W", "X", "Y", "Z"};

    private static String jwtId() {
        StringBuffer stringBuffer = new StringBuffer();
        String uuid = UUID.randomUUID().toString().replace("-", "");
        for (int i = 0; i < 8; i++) { // 32 -> 8
            String str = uuid.substring(i * 4, i * 4 + 4);
            // 16进制为基解析
            int strInteger = Integer.parseInt(str, 16);
            // 0x3E -> 字典总数 62
            stringBuffer.append(CHARS[strInteger % 0x3E]);
        }
        return stringBuffer.toString();
    }
}
