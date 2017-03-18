package com.meng.client.security.oauth2;

import com.meng.client.model.oauth2.OAuth2Token;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthBearerClientRequest;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.oltu.oauth2.client.response.OAuthResourceResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * @author xindemeng
 */
public class OAuth2Realm extends AuthorizingRealm
{
    private String clientId;
    private String clientSecret;
    private String accessTokenUrl;
    private String userInfoUrl;
    private String redirectUrl;

    //表示此Realm只支持OAuth2Token类型
    @Override
    public boolean supports(AuthenticationToken token)
    {
        return token instanceof OAuth2Token;
    }

    //授权
    //如果需要AuthorizationInfo信息，可以根据此处获取的用户名再根据自己的业务规则去获取。
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals)
    {
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        return authorizationInfo;
    }

    //认证
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException
    {
        OAuth2Token oAuth2Token = (OAuth2Token) token;
        String authCode = oAuth2Token.getAuthCode();
        String account = extractAccount(authCode);

        SimpleAuthenticationInfo authenticationInfo =
                new SimpleAuthenticationInfo(account, authCode, getName());

        return authenticationInfo;
    }

    private String extractAccount(String authCode)
    {
        try
        {
            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());

            OAuthClientRequest accessTokenRequest = OAuthClientRequest
                    .tokenLocation(accessTokenUrl)
                    .setGrantType(GrantType.AUTHORIZATION_CODE)
                    .setClientId(clientId)
                    .setClientSecret(clientSecret)
                    .setCode(authCode)
                    .setRedirectURI(redirectUrl)
                    .buildQueryMessage();

            //获取access token
            OAuthAccessTokenResponse oAuthAccessTokenResponse =
                    oAuthClient.accessToken(accessTokenRequest, OAuth.HttpMethod.POST);
            String accessToken = oAuthAccessTokenResponse.getAccessToken();
            Long expiresIn = oAuthAccessTokenResponse.getExpiresIn();

            //获取user info
            OAuthClientRequest userInfoRequest =
                    new OAuthBearerClientRequest(userInfoUrl)
                    .setAccessToken(accessToken)
                    .buildQueryMessage();
            OAuthResourceResponse resourceResponse = oAuthClient.resource(
                    userInfoRequest, OAuth.HttpMethod.GET, OAuthResourceResponse.class);
            String account = resourceResponse.getBody();
            return account;
        } catch (OAuthSystemException e)
        {
            e.printStackTrace();
        } catch (OAuthProblemException e)
        {
            e.printStackTrace();
        }
        return null;
    }

    public void setClientId(String clientId)
    {
        this.clientId = clientId;
    }

    public void setClientSecret(String clientSecret)
    {
        this.clientSecret = clientSecret;
    }

    public void setAccessTokenUrl(String accessTokenUrl)
    {
        this.accessTokenUrl = accessTokenUrl;
    }

    public void setUserInfoUrl(String userInfoUrl)
    {
        this.userInfoUrl = userInfoUrl;
    }

    public void setRedirectUrl(String redirectUrl)
    {
        this.redirectUrl = redirectUrl;
    }
}
