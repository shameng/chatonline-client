package com.meng.client.security.oauth2.filter;

import com.meng.client.model.oauth2.OAuth2Token;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.util.SavedRequest;
import org.apache.shiro.web.util.WebUtils;
import org.springframework.util.StringUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

import static org.apache.shiro.web.util.WebUtils.getContextPath;

/**
 * @author xindemeng
 *
 * OAuth2认证过滤器
 */
public class OAuth2AuthenticationFilter extends AuthenticatingFilter
{
    private static final String OAUTH2_ERROR_PARAM = "error";
    private static final String OAUTH2_ERROR_DESCRIPTION_PARAM = "error_description";
    private static final String OAUTH2_ERROR_URI_PARAM = "error_uri";
    private static final String OAUTH2_STATE_PARAM = "state";

    //OAuth2 auth code参数名
    public String authCodeParam = "code";
    //客户端id
    private String clientId;
    //服务器端登录成功/失败后重定向到的客户端地址
    private String redirectUrl;
    //oauth2服务器响应类型
    private String responseType = "code";

    private String failureUrl;

    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception
    {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String authCode = httpServletRequest.getParameter(getAuthCodeParam());
        return new OAuth2Token(authCode);
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
    {
        return false;
    }

    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception
    {
        String error = request.getParameter(OAUTH2_ERROR_PARAM);
        String errorDescription = request.getParameter(OAUTH2_ERROR_DESCRIPTION_PARAM);
        //如果服务端返回了错误
        if (!StringUtils.isEmpty(error))
        {
            WebUtils.issueRedirect(request, response,
                    failureUrl + "?error=" + error + "&errorDescription=" + errorDescription);
            return false;
        }

        Subject subject = getSubject(request, response);
        if (!subject.isAuthenticated())
        {
            if (StringUtils.isEmpty(request.getParameter(getAuthCodeParam())))
            {
                //返回登陆页面
                saveRequestAndRedirectToLogin(request, response);
                return false;
            }
            //执行登陆操作
            else
                return executeLogin(request, response);
        }
        else
        {
            issueSuccessRedirect(request, response);
            return false;
        }
    }

    @Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request, ServletResponse response) throws Exception
    {
        issueSuccessRedirect(request, response);
        return false;
    }

    @Override
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request, ServletResponse response)
    {
        Subject subject = getSubject(request, response);
        if (subject.isAuthenticated() || subject.isRemembered())
            try
            {
                issueSuccessRedirect(request, response);
            } catch (Exception e1)
            {
                e1.printStackTrace();
            }
        else
            try
            {
                WebUtils.issueRedirect(request, response, getFailureUrl());
            } catch (IOException e1)
            {
                e1.printStackTrace();
            }
        return false;
    }

    //重写该方法，避免登陆授权成功后再次访问"/oauth2-login"
    @Override
    protected void issueSuccessRedirect(ServletRequest request, ServletResponse response) throws Exception
    {
        String successUrl = getSuccessUrl();
        boolean contextRelative = true;
        SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(request);
        if (savedRequest != null && savedRequest.getMethod().equalsIgnoreCase(AccessControlFilter.GET_METHOD)) {
            String saveUrl = savedRequest.getRequestUrl();
            saveUrl = getPathWithinApplication(WebUtils.toHttp(request), saveUrl);
            if (!pathsMatch("/oauth2-login", saveUrl))
                successUrl = saveUrl;
        }

        if (successUrl == null) {
            throw new IllegalStateException("Success URL not available via saved request or via the " +
                    "successUrlFallback method parameter. One of these must be non-null for " +
                    "issueSuccessRedirect() to work.");
        }

        WebUtils.issueRedirect(request, response, successUrl, null, contextRelative);
    }

    private String getPathWithinApplication(HttpServletRequest request, String requestUri)
    {
        String contextPath = getContextPath(request);
        if (StringUtils.startsWithIgnoreCase(requestUri, contextPath)) {
            // Normal case: URI contains context path.
            String path = requestUri.substring(contextPath.length());
            return (StringUtils.hasText(path) ? path : "/");
        } else {
            // Special case: rather unusual.
            return requestUri;
        }
    }

    public String getAuthCodeParam()
    {
        return authCodeParam;
    }

    public void setAuthCodeParam(String authCodeParam)
    {
        this.authCodeParam = authCodeParam;
    }

    public String getClientId()
    {
        return clientId;
    }

    public void setClientId(String clientId)
    {
        this.clientId = clientId;
    }

    public String getRedirectUrl()
    {
        return redirectUrl;
    }

    public void setRedirectUrl(String redirectUrl)
    {
        this.redirectUrl = redirectUrl;
    }

    public String getResponseType()
    {
        return responseType;
    }

    public void setResponseType(String responseType)
    {
        this.responseType = responseType;
    }

    public String getFailureUrl()
    {
        return failureUrl;
    }

    public void setFailureUrl(String failureUrl)
    {
        this.failureUrl = failureUrl;
    }
}
