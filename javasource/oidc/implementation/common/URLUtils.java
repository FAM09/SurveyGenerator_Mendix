package oidc.implementation.common;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;
import com.mendix.core.Core;
import com.mendix.logging.ILogNode;
import com.mendix.m2ee.api.IMxRuntimeRequest;

public final class URLUtils {

    private static final ILogNode _logNode = Core.getLogger(Constants.LOG_NODE);
    private static final String HTTP = "http";
    private static final String HTTPS = "https";

    // Mendix constant names for security configuration
    private static final String ENABLE_MULTI_DOMAIN_CONSTANT = "OIDC.EnableMultiDomainSupport";
    private static final String ALLOWED_HOSTS_CONSTANT = "OIDC.AllowedHosts";

    // Regex to extract 'host' from RFC 7239 Forwarded header
    private static final Pattern FORWARDED_HOST_PATTERN = Pattern.compile(
            "host=\"?([^\";,\\s]+)\"?", Pattern.CASE_INSENSITIVE);

    // Regex to extract 'proto' from RFC 7239 Forwarded header
    private static final Pattern FORWARDED_PROTO_PATTERN = Pattern.compile(
            "proto=\"?([^\";,\\s]+)\"?", Pattern.CASE_INSENSITIVE);

    // HTTP header name constants
    private static final String HEADER_FORWARDED = "Forwarded";
    private static final String HEADER_X_FORWARDED_HOST = "X-Forwarded-Host";
    private static final String HEADER_X_FORWARDED_PROTO = "X-Forwarded-Proto";
    private static final String HEADER_X_FORWARDED_SCHEME = "X-Forwarded-Scheme";
    private static final String HEADER_X_FORWARDED_PORT = "X-Forwarded-Port";
    private static final String HEADER_X_ORIGINAL_HOST = "X-Original-Host";

    private URLUtils() {
    }

    public static String ensureEndsWithSlash(String text) {
        return text.endsWith("/") ? text : text + "/";
    }

    // Resolves the application URL from the incoming request using headers and config
    public static String getApplicationUrlFromRequest(IMxRuntimeRequest request) {
        String configuredRootUrl = getDefaultAppRootUrl();

        // Feature flag: if disabled, always return the configured ApplicationRootUrl
        if (!isMultiDomainEnabled()) {
            _logNode.debug("Dynamic URL resolution is disabled, returning configured ApplicationRootUrl");
            return configuredRootUrl;
        }

        // Resolve hostname from request headers using priority chain
        String serverName = getServerName(request);
        if (serverName == null) {
            _logNode.debug("No hostname could be resolved from request headers, returning configured ApplicationRootUrl");
            return configuredRootUrl;
        }

        // Validate resolved hostname against AllowedHosts list
        if (!isHostAllowed(serverName)) {
            _logNode.warn("Resolved hostname '" + serverName + "' is not in the AllowedHosts list, falling back to configured ApplicationRootUrl");
            return configuredRootUrl;
        }

        // Build the full URL from resolved hostname, scheme, port and path
        try {
            final String scheme;
            final int serverPort;

            // When proxy sets host but not scheme, derive scheme/port from config to avoid internal http:8080
            if (hasAnyHostProxyHeader(request) && !hasAnySchemeProxyHeader(request) && configuredRootUrl != null) {
                scheme = extractSchemeFromUrl(configuredRootUrl);
                serverPort = extractPortFromUrl(configuredRootUrl, scheme);

            } else {
                scheme = isHttps(request) ? HTTPS : HTTP;
                serverPort = getServerPort(request, scheme);
            }

            String path = getApplicationRootPath();
            boolean isDefaultPort = (HTTP.equalsIgnoreCase(scheme) && serverPort == 80)
                    || (HTTPS.equalsIgnoreCase(scheme) && serverPort == 443);
            final URI appUri = new URI(scheme, null, serverName, isDefaultPort ? -1 : serverPort, path, null, null);
            String result = appUri.toString();
            _logNode.debug("Resolved application URL from request: " + result);
            return result;
        } catch (URISyntaxException e) {
            _logNode.warn("Failed to construct application URL from request, falling back to default: " + e.getMessage(), e);
            return configuredRootUrl;
        }
    }

    // Checks if request has any proxy headers that indicate the hostname
    private static boolean hasAnyHostProxyHeader(IMxRuntimeRequest request) {
        String forwarded = StringUtils.trimToNull(request.getHeader(HEADER_FORWARDED));
        if (forwarded != null && extractForwardedHost(forwarded) != null) return true;
        return StringUtils.trimToNull(request.getHeader(HEADER_X_FORWARDED_HOST)) != null
                || StringUtils.trimToNull(request.getHeader(HEADER_X_ORIGINAL_HOST)) != null;
    }

    // Checks if request has any proxy headers that indicate the scheme/protocol
    private static boolean hasAnySchemeProxyHeader(IMxRuntimeRequest request) {
        String forwarded = StringUtils.trimToNull(request.getHeader(HEADER_FORWARDED));
        if (forwarded != null && extractForwardedProto(forwarded) != null) return true;
        if (StringUtils.trimToNull(request.getHeader(HEADER_X_FORWARDED_PROTO)) != null) return true;
        if (StringUtils.trimToNull(request.getHeader(HEADER_X_FORWARDED_SCHEME)) != null) return true;
        return false;
    }

    // Extracts scheme from a URL string, defaults to http
    private static String extractSchemeFromUrl(String url) {
        if (url == null) return HTTP;
        try {
            String scheme = new URI(url).getScheme();
            return scheme != null ? scheme : HTTP;
        } catch (URISyntaxException e) {
            _logNode.warn("Failed to parse scheme from URL '" + url + "', falling back to default: " + e.getMessage());
            return HTTP;
        }
    }

    // Extracts port from a URL string, defaults to 443 (https) or 80 (http)
    private static int extractPortFromUrl(String url, String scheme) {
        if (url != null) {
            try {
                int port = new URI(url).getPort();
                if (port > 0) return port;
            } catch (URISyntaxException e) {
                _logNode.warn("Failed to parse port from URL '" + url + "': " + e.getMessage());
            }
        }
        return HTTPS.equals(scheme) ? 443 : 80;
    }

    // Resolves hostname from headers: Forwarded → X-Forwarded-Host → X-Original-Host → Host
    private static String getServerName(IMxRuntimeRequest request) {
        // 1. RFC 7239 Forwarded header (official standard)
        String forwarded = StringUtils.trimToNull(request.getHeader(HEADER_FORWARDED));
        if (forwarded != null) {
            String forwardedHost = extractForwardedHost(forwarded);
            if (forwardedHost != null) {
                _logNode.debug("Server name resolved from Forwarded header: " + forwardedHost);
                return forwardedHost;
            }
        }

        // 2. X-Forwarded-Host (de facto standard, used by most reverse proxies)
        String xForwardedHost = extractHost(request.getHeader(HEADER_X_FORWARDED_HOST));
        if (xForwardedHost != null) {
            _logNode.debug("Server name resolved from X-Forwarded-Host header: " + xForwardedHost);
            return xForwardedHost;
        }

        // 3. X-Original-Host (Azure Application Gateway, some nginx setups)
        String xOriginalHost = extractHost(request.getHeader(HEADER_X_ORIGINAL_HOST));
        if (xOriginalHost != null) {
            _logNode.debug("Server name resolved from X-Original-Host header: " + xOriginalHost);
            return xOriginalHost;
        }

        // 4. Servlet Host header (may be internal hostname behind proxy)
        String servletServerName = request.getHttpServletRequest().getServerName();
        if (servletServerName != null) {
            _logNode.debug("Server name resolved from servlet Host header: " + servletServerName);
            return servletServerName;
        }

        return null;
    }

    // Extracts hostname from a header value, handling comma-separated lists and host:port format
    private static String extractHost(String headerValue) {
        String value = StringUtils.trimToNull(headerValue);
        if (value == null) {
            return null;
        }
        // Multiple proxies: take the first (client-facing) value
        if (value.contains(",")) {
            value = StringUtils.trimToNull(value.split(",")[0]);
            if (value == null) {
                return null;
            }
        }
        return stripBracketsAndPort(value);
    }

    // Extracts host from RFC 7239 Forwarded header (e.g. "host=example.com;proto=https")
    private static String extractForwardedHost(String forwardedHeader) {
        Matcher matcher = FORWARDED_HOST_PATTERN.matcher(forwardedHeader);
        if (matcher.find()) {
            String host = StringUtils.trimToNull(matcher.group(1));
            return stripBracketsAndPort(host);
        }
        return null;
    }

    // Strips IPv6 brackets and port from a host value (e.g. "[::1]:8080" → "::1", "host:443" → "host")
    private static String stripBracketsAndPort(String host) {
        if (host == null) {
            return null;
        }
        if (host.startsWith("[")) {
            int bracketEnd = host.indexOf(']');
            if (bracketEnd > 0) {
                return host.substring(1, bracketEnd);
            }
        } else if (host.contains(":")) {
            return StringUtils.trimToNull(host.substring(0, host.lastIndexOf(':')));
        }
        return host;
    }

    // Extracts proto from RFC 7239 Forwarded header (e.g. "proto=https")
    private static String extractForwardedProto(String forwardedHeader) {
        Matcher matcher = FORWARDED_PROTO_PATTERN.matcher(forwardedHeader);
        if (matcher.find()) {
            return StringUtils.trimToNull(matcher.group(1));
        }
        return null;
    }

    // Resolves port: Forwarded header → X-Forwarded-Port → servlet port → default (443/80)
    private static int getServerPort(IMxRuntimeRequest request, String scheme) {
        int port = extractPortFromForwardedHeader(request);
        if (port > 0) return port;

        port = extractPortFromXForwardedPort(request);
        if (port > 0) return port;

        // If behind a proxy, the servlet port is internal and should not be used
        if (hasAnyHostProxyHeader(request)) {
            return getDefaultPort(scheme);
        }

        port = request.getHttpServletRequest().getServerPort();
        if (port > 0) {
            return port;
        }
        return getDefaultPort(scheme);
    }

    // Extracts port from RFC 7239 Forwarded header's host directive (e.g. host=example.com:8080)
    private static int extractPortFromForwardedHeader(IMxRuntimeRequest request) {
        String forwarded = StringUtils.trimToNull(request.getHeader(HEADER_FORWARDED));
        if (forwarded != null) {
            Matcher matcher = FORWARDED_HOST_PATTERN.matcher(forwarded);
            if (matcher.find()) {
                String hostValue = matcher.group(1);
                if (hostValue != null && !hostValue.startsWith("[") && hostValue.contains(":")) {
                    try {
                        return Integer.parseInt(hostValue.substring(hostValue.lastIndexOf(':') + 1));
                    } catch (NumberFormatException e) {
                        _logNode.warn("Invalid port in Forwarded header host value '" + hostValue + "'");
                    }
                }
            }
        }
        return -1;
    }

    // Extracts port from X-Forwarded-Port header
    private static int extractPortFromXForwardedPort(IMxRuntimeRequest request) {
        String forwardedPort = StringUtils.trimToNull(request.getHeader(HEADER_X_FORWARDED_PORT));
        if (forwardedPort != null) {
            // Handle comma-separated values (multi-proxy): take the first
            if (forwardedPort.contains(",")) {
                forwardedPort = StringUtils.trimToNull(forwardedPort.split(",")[0]);
            }
            if (forwardedPort != null) {
                try {
                    return Integer.parseInt(forwardedPort);
                } catch (NumberFormatException e) {
                    _logNode.warn("Invalid X-Forwarded-Port header value '" + forwardedPort + "', falling back");
                }
            }
        }
        return -1;
    }

    private static int getDefaultPort(String scheme) {
        return HTTPS.equalsIgnoreCase(scheme) ? 443 : 80;
    }

    // Extracts the path component from the configured ApplicationRootUrl
    public static String getApplicationRootPath() {
        try {
            String rootUrl = StringUtils.trimToNull(Core.getConfiguration().getApplicationRootUrl());
            if (rootUrl == null) {
                return "/";
            }
            URI uri = new URI(rootUrl);
            String path = StringUtils.trimToNull(uri.getPath());
            if (path == null) {
                return "/";
            }
            if (!path.startsWith("/")) {
                path = "/" + path;
            }
            if (path.length() > 1 && path.endsWith("/")) {
                path = path.substring(0, path.length() - 1);
            }
            return path;
        } catch (URISyntaxException e) {
            _logNode.warn("Failed to parse application root URL, falling back to '/': " + e.getMessage());
            return "/";
        }
    }

    // Returns the configured ApplicationRootUrl from Mendix runtime settings
    public static String getDefaultAppRootUrl() {
        return Core.getConfiguration().getApplicationRootUrl();
    }

    // Checks if the dynamic URL feature is enabled via the OIDC.EnableMultiDomainSupport constant
    private static boolean isMultiDomainEnabled() {
        Object value = Core.getConfiguration().getConstantValue(ENABLE_MULTI_DOMAIN_CONSTANT);
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        // Default: disabled (safe by default)
        return false;
    }

    // Validates hostname against the OIDC.AllowedHosts constant.
    // Supports: exact match, wildcard subdomain (.example.com), and wildcard (*)
    private static boolean isHostAllowed(String hostname) {
        Object value = Core.getConfiguration().getConstantValue(ALLOWED_HOSTS_CONSTANT);
        if (!(value instanceof String)) {
            // No AllowedHosts configured: reject all (safe by default)
            return false;
        }
        String allowedHostsStr = StringUtils.trimToNull((String) value);
        if (allowedHostsStr == null) {
            return false;
        }

        String lowerHostname = hostname.toLowerCase();
        String[] allowedHosts = allowedHostsStr.split("[,\\s]+");
        for (String entry : allowedHosts) {
            String allowed = StringUtils.trimToNull(entry);
            if (allowed == null) {
                continue;
            }
            allowed = allowed.toLowerCase();

            // Wildcard: allow anything
            if ("*".equals(allowed)) {
                return true;
            } else if (allowed.startsWith(".")) {
                // Subdomain wildcard: .example.com matches example.com and *.example.com
                String domain = allowed.substring(1); // "example.com"
                if (lowerHostname.equals(domain) || lowerHostname.endsWith(allowed)) {
                    return true;
                }
            } else if (lowerHostname.equals(allowed)) {
                // Exact match (case-insensitive)
                return true;
            }
        }
        return false;
    }

    public static String removeTrailingSlash(String value) {
        if (value != null && value.length() > 1 && value.endsWith("/")) {
            return value.substring(0, value.length() - 1);
        }
        return value;
    }

    // Determines HTTPS: Forwarded proto → X-Forwarded-Proto → X-Forwarded-Scheme → request.isSecure()
    public static boolean isHttps(IMxRuntimeRequest request) {
        String forwarded = StringUtils.trimToNull(request.getHeader(HEADER_FORWARDED));
        if (forwarded != null) {
            String proto = extractForwardedProto(forwarded);
            if (proto != null) {
                return HTTPS.equalsIgnoreCase(proto);
            }
        }

        var hasProtoHttps = hasHeaderValue(request, HEADER_X_FORWARDED_PROTO, "https");
        var hasSchemeHttps = hasHeaderValue(request, HEADER_X_FORWARDED_SCHEME, "https");
        if (hasProtoHttps || hasSchemeHttps) {
            return true;
        }
        return request.getHttpServletRequest().isSecure();
    }

    private static boolean hasHeaderValue(IMxRuntimeRequest request, String headerName, String value) {
        String header = request.getHeader(headerName);
        if (header == null) return false;
        // Handle comma-separated values (multi-proxy): check the first value
        if (header.contains(",")) {
            header = header.split(",")[0].trim();
        }
        return value.equalsIgnoreCase(header.trim());
    }
}