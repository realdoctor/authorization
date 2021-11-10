package com.realdoctor.authorization.token.impl;

import com.realdoctor.authorization.JwtConfig;
import com.realdoctor.authorization.token.TokenManager;

/**
 * Token管理的基础类
 * 
 * @author xl.liu
 */
public abstract class AbstractTokenManager implements TokenManager {

    public boolean flushExpireAfterOperation = true;
    public boolean singleToken               = false;
    /**
     * jwt签名密钥
     */
    public String  signSecret                = JwtConfig.JWT_SECRET;
    /**
     * 有效时间
     */
    public int     expiresIn                 = JwtConfig.TOKEN_EXPIRES_SECONDS;

    public boolean isSingleToken() {
        return singleToken;
    }

    public void setFlushExpireAfterOperation(boolean flushExpireAfterOperation) {
        this.flushExpireAfterOperation = flushExpireAfterOperation;
    }

    public void setSingleToken(boolean singleToken) {
        this.singleToken = singleToken;
    }

    public void setSignSecret(String signSecret) {
        this.signSecret = signSecret;
        JwtConfig.JWT_SECRET = signSecret;
    }

    public void setExpiresIn(int expiresIn) {
        this.expiresIn = expiresIn;
        JwtConfig.TOKEN_EXPIRES_SECONDS = expiresIn;
    }

    @Override
    public void delRelationshipByKey(String key) {
        delSingleRelationshipByKey(key);
    }

    @Override
    public void createRelationship(String key, String token) {
        // 根据设置的每个用户是否只允许绑定一个Token
        if (singleToken) {
            createSingleRelationship(key, token);
        } else {
            createMultipleRelationship(key, token);
        }
    }

    /**
     * 一个用户只能绑定一个Token时通过Key删除关联关系
     * 
     * @param key
     */
    protected abstract void delSingleRelationshipByKey(String key);

    /**
     * 一个用户可以绑定多个Token时创建关联关系
     * 
     * @param key
     * @param token
     */
    protected abstract void createMultipleRelationship(String key, String token);

    /**
     * 一个用户只能绑定一个Token时创建关联关系
     * 
     * @param key
     * @param token
     */
    protected abstract void createSingleRelationship(String key, String token);

    /**
     * 在操作后刷新Token的过期时间
     * 
     * @param key
     * @param token
     */
    protected abstract void flushExpireAfterOperation(String key, String token);

    @Override
    public String getKey(String token) {
        String key = getKeyByToken(token);
        // 根据设置，在每次有效操作后刷新过期时间
        if (key != null && flushExpireAfterOperation) {
            flushExpireAfterOperation(key, token);
        }
        return key;
    }

    /**
     * 通过Token获得Key
     * 
     * @param token
     * @return
     */
    protected abstract String getKeyByToken(String token);

}
