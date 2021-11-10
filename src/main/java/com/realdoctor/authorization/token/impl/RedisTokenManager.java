package com.realdoctor.authorization.token.impl;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import com.realdoctor.authorization.JwtConfig;

/**
 * 使用Redis存储Token
 * 
 * @author xl.liu
 */
@Component
@ConfigurationProperties(prefix = "jwt")
public class RedisTokenManager extends AbstractTokenManager {

    public RedisTemplate<String, Object> redisTemplate;

    @Autowired
    public void setRedisTemplate(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    protected void createSingleRelationship(String key, String token) {
        String oldToken = get(formatKey(key));
        if (oldToken != null) {
            delete(formatToken(oldToken));
        }
        set(formatToken(token), key, JwtConfig.TOKEN_EXPIRES_SECONDS);
        set(formatKey(key), token, JwtConfig.TOKEN_EXPIRES_SECONDS);
    }

    @Override
    protected void createMultipleRelationship(String key, String token) {
        set(formatToken(token), key, JwtConfig.TOKEN_EXPIRES_SECONDS);
    }

    @Override
    protected void delSingleRelationshipByKey(String key) {
        String token = getToken(key);
        if (token != null) {
            delete(formatKey(key), formatToken(token));
        }
    }

    @Override
    public void delRelationshipByToken(String token) {
        String key = getKey(token);
        if (key != null) {
            delete(formatKey(key), formatToken(token));
        }
    }

    @Override
    protected void flushExpireAfterOperation(String key, String token) {
        if (singleToken) {
            expire(formatKey(key), JwtConfig.TOKEN_EXPIRES_SECONDS);
        }
        expire(formatToken(token), JwtConfig.TOKEN_EXPIRES_SECONDS);
    }

    @Override
    public String getKeyByToken(String token) {
        return get(formatToken(token));
    }

    public String getToken(String key) {
        return get(formatKey(key));
    }

    public void refreshRelationship(String key, String token) {
        final int holdSeconds = 300;// 延续5分钟
        if (singleToken) {
            String oldToken = get(formatKey(key));
            if (oldToken != null) {
                expire(formatToken(oldToken), holdSeconds);
            }
            set(formatKey(key), token, JwtConfig.TOKEN_EXPIRES_SECONDS);
        }
        set(formatToken(token), key, JwtConfig.TOKEN_EXPIRES_SECONDS);
    }

    /**
     * @param key
     * @return
     */
    private String get(String key) {
        Object obj = getCacheObject(key);
        if (obj == null) {
            return null;
        }
        return String.valueOf(obj);
    }

    private void set(String key, String value, int expireSeconds) {
        setCacheObject(key, value, Long.valueOf(expireSeconds), TimeUnit.SECONDS);
    }

    private void expire(String key, int seconds) {
        expire(key, seconds, TimeUnit.SECONDS);
    }

    private void delete(String... keys) {
        if (keys != null && keys.length > 0) {
            if (keys.length == 1) {
                redisTemplate.delete(keys[0]);
            } else {
                redisTemplate.delete(arrayToList(keys));
            }
        }
    }

    public String formatKey(String key) {
        return JwtConfig.formatKey(key);
    }

    public String formatToken(String token) {
        return JwtConfig.formatToken(token);
    }

    /**
     * @param arrays
     * @return
     */
    public static List<String> arrayToList(String[] arrays) {
        List<String> result =
                Stream.of(arrays).filter(Objects::nonNull).collect(Collectors.toList());
        return result;
    }

    public boolean expire(String key, long time) {
        return redisTemplate.expire(key, time, TimeUnit.SECONDS);
    }

    /**
     * 设置过期时间
     * 
     * @param key 键
     * @param time 时间(秒)
     * @param unit
     * @return
     */
    public boolean expire(final String key, final long timeout, final TimeUnit unit) {
        return redisTemplate.expire(key, timeout, unit);
    }

    /**
     * 缓存基本的对象，Integer、String、实体类等
     * 
     * @param key 缓存的键值
     * @param value 缓存的值
     * @return 缓存的对象
     */
    public boolean setCacheObject(String key, Object value) {
        try {
            redisTemplate.opsForValue().set(key, value);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 缓存基本的对象，Integer、String、实体类等
     * 
     * @param key 缓存的键值
     * @param value 缓存的值
     * @param timeout 过期时间
     * @return 缓存的对象
     */
    public boolean setCacheObject(String key, Object value, Long timeout, TimeUnit unit) {
        if (value == null) {
            return false;
        }
        try {
            if (timeout != null) {
                redisTemplate.opsForValue().set(key, value, timeout, unit);
            } else {
                redisTemplate.opsForValue().set(key, value);
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 获得缓存的基本对象。
     * 
     * @param key 缓存键值
     * @param operation
     * @return 缓存键值对应的数据
     */
    public Object getCacheObject(String key) {
        return key == null ? null : redisTemplate.opsForValue().get(key);
    }
}
