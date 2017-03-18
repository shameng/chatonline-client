package com.meng.client.model.oauth2;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * @author xindemeng
 *
 * 类似于UsernamePasswordToken和CasToken；用于存储oauth2服务端返回的auth code。
 */
public class OAuth2Token implements AuthenticationToken
{
    //授权码
    private String authCode;
    private Object principal;

    public OAuth2Token(){}

    public OAuth2Token(String authCode)
    {
        this.authCode = authCode;
    }

    //返回凭证是授权码
    public Object getCredentials()
    {
        return authCode;
    }

    public void setAuthCode(String authCode)
    {
        this.authCode = authCode;
    }

    public void setPrincipal(Object principal)
    {
        this.principal = principal;
    }

    public String getAuthCode()
    {
        return authCode;
    }

    public Object getPrincipal()
    {
        return principal;
    }
}
