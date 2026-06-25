package oidc.implementation;

import java.util.Arrays;
import java.util.function.Predicate;

import org.apache.commons.lang3.StringUtils;
import io.netty.handler.codec.http.cookie.CookieHeaderNames;
import io.netty.handler.codec.http.cookie.DefaultCookie;
import io.netty.handler.codec.http.cookie.ServerCookieEncoder;
import com.mendix.m2ee.api.IMxRuntimeRequest;
import com.mendix.m2ee.api.IMxRuntimeResponse;
import com.mendix.core.Core;
import oidc.implementation.common.URLUtils;
import oidc.proxies.constants.Constants;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

public final class CookieUtil {

    public static final String NONCE_COOKIE_DOMAIN = "";
    public static final String COOKIE_HOST_PREFIX = "__Host-";
    public static final String COOKIE_SECURE_PREFIX = "__Secure-";
    public static final String NONCE_COOKIE_NAME = "OIDCSSONONCE";
    public static final String SET_COOKIE = "Set-Cookie";
    private CookieUtil() {
    }

    public static String createCookie(IMxRuntimeRequest request, String name, String value, String path, String domain, CookieHeaderNames.SameSite sameSite, int maxAge) {
        var isHttps = URLUtils.isHttps(request);
        CookieNameAndDomain cookieInfo = getCookieNameAndDomain(isHttps, path, name, domain);

        DefaultCookie nettyCookie = new DefaultCookie(cookieInfo.cookieName(), value);
        nettyCookie.setHttpOnly(true);
        nettyCookie.setSecure(isHttps);
        nettyCookie.setPath(path);
        nettyCookie.setSameSite(sameSite);
        if (StringUtils.isNotBlank(cookieInfo.domain())) {
            nettyCookie.setDomain(cookieInfo.domain());
        }
        nettyCookie.setMaxAge(maxAge);

        return ServerCookieEncoder.STRICT.encode(nettyCookie);
    }

    private record CookieNameAndDomain(String cookieName, String domain) {}

    private static CookieNameAndDomain getCookieNameAndDomain(boolean isHttps, String path, String name, String domain) {
        if (isHttps) {
            if ("/".equals(path)) {
                return new CookieNameAndDomain(COOKIE_HOST_PREFIX + name, null);
            } else {
                return new CookieNameAndDomain(COOKIE_SECURE_PREFIX + name, domain);
            }
        } else {
            return new CookieNameAndDomain(name, domain);
        }
    }

    public static String getCookie(IMxRuntimeRequest request, String cookieName) {
        HttpServletRequest servletRequest = request.getHttpServletRequest();
        var isHttps = URLUtils.isHttps(request);
        var secureCookieName = isHttps ? COOKIE_HOST_PREFIX + cookieName : cookieName;
        Cookie[] cookies = servletRequest.getCookies();
        if (cookies == null)
            return null;

        if (isHttps) {
            String hostPrefixedName = COOKIE_HOST_PREFIX + cookieName;
            String securePrefixedName = COOKIE_SECURE_PREFIX + cookieName;

            return getFirstCookieValue(cookies, cookie -> cookie.getName().equals(hostPrefixedName) || cookie.getName().equals(securePrefixedName));
        } else {
            return getFirstCookieValue(cookies, cookie -> cookie.getName().equals(cookieName));
        }
    }

    private static String getFirstCookieValue(Cookie[] cookies, Predicate<Cookie> filter) {
        return Arrays.stream(cookies)
                .filter(filter)
                .findFirst()
                .map(Cookie::getValue)
                .orElse(null);
    }

    public static void setNonceCookie(IMxRuntimeRequest request, IMxRuntimeResponse response, String state, String nonce) {
        String nonceCookieName = getNonceCookieName(state);
        String cookiePath = URLUtils.getApplicationRootPath();
        int maxAgeInSeconds = (Constants.getDeleteAuthAttemptsInMinutes().intValue() + 5) * 60;
        String cookieHeader = createCookie(request, nonceCookieName, nonce, cookiePath, NONCE_COOKIE_DOMAIN, CookieHeaderNames.SameSite.Lax, maxAgeInSeconds);
        response.getHttpServletResponse().addHeader(SET_COOKIE, cookieHeader);
    }

    public static void unsetNonceCookie(IMxRuntimeRequest request, IMxRuntimeResponse response, String state) {
        String nonceCookieName = getNonceCookieName(state);
        String cookiePath = URLUtils.getApplicationRootPath();
        String cookieHeader = createCookie(request, nonceCookieName, "", cookiePath, NONCE_COOKIE_DOMAIN, CookieHeaderNames.SameSite.Lax, 0);
        response.getHttpServletResponse().addHeader(SET_COOKIE, cookieHeader);
    }

    public static String getNonceCookieName(String state) {
        return NONCE_COOKIE_NAME + "_" + state;
    }

}
