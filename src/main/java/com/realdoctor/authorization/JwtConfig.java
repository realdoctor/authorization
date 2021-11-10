package com.realdoctor.authorization;

/**
 * 全局配置常量
 * 
 * @author xl.liu
 */
public final class JwtConfig {

    /**
     * 当前登录用户id的字段名
     */
    public static final String CURRENT_USER_ID               = "CURRENT_USER_ID";

    /**
     * token有效期，单位秒
     */
    public static String       JWT_SECRET                    = "35c618bfa68e5a8ec8d67d8901b5b2e3";
    public static int          TOKEN_EXPIRES_SECONDS         = 30 * 60; // 30分钟
    public static int          TOKEN_REFRESH_EXPIRES_SECONDS = 7 * 24 * 60 * 60; // 7天

    /**
     * 存放Authorization的header字段
     */
    public static final String AUTHORIZATION                 = "Authorization";
    public static final String TOKEN_PREFIX                  = "Bearer ";

    /**
     * Redis中Key的前缀
     */
    public static final String REDIS_KEY_PREFIX              = "AUTHORIZATION_KEY_";

    /**
     * Redis中Token的前缀
     */
    public static final String REDIS_TOKEN_PREFIX            = "AUTHORIZATION_TOKEN_";

    public static String formatKey(String key) {
        return JwtConfig.REDIS_KEY_PREFIX.concat(key);
    }

    public static String formatToken(String token) {
        return JwtConfig.REDIS_TOKEN_PREFIX.concat(token);
    }
}
