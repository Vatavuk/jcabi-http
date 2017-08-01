package com.jcabi.http.wire;

import com.jcabi.aspects.Immutable;
import com.jcabi.http.*;
import com.sun.deploy.util.StringUtils;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import javax.ws.rs.core.HttpHeaders;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Wire with HTTP digest authentication based on provided user credentials.
 * <p>
 * <p>This wire converts user info from URI into
 * {@code "Authorization"} HTTP header, for example:
 * <p>
 * <pre> String html = new JdkRequest("http://jeff:12345@example.com")
 *   .through(BasicAuthWire.class)
 *   .fetch()
 *   .body();</pre>
 * <p>
 * <p>In this example, an additional HTTP header {@code Authorization}
 * will be added with a value {@code Basic amVmZjoxMjM0NQ==}.
 * <p>
 * <p>The class is immutable and thread-safe.
 *
 * @author Vedran Grgo Vatavuk (123vgv@gmail.com)
 * @version $Id$
 * @see <a href="http://tools.ietf.org/html/rfc2617">RFC 2617 "HTTP Authentication: Basic and Digest Access Authentication"</a>
 * @since 0.10
 */
@Immutable
@ToString(of = "origin")
@EqualsAndHashCode(of = "origin")
public class DigestAuthWire implements Wire {

    /**
     * Original wire.
     */
    private final transient Wire origin;

    /**
     * The username to use for authentication.
     */
    private final String username;

    /**
     * The password to use for authentication.
     */
    private final String password;

    public DigestAuthWire(final Wire origin, final String username, final String password) {
        this.origin = origin;
        this.username = username;
        this.password = password;
    }

    @Override
    public Response send(final Request req, final String home, final String method,
        final Collection<Map.Entry<String, String>> headers, final InputStream content, final int connect,
        final int read) throws IOException {

        Response response = this.origin.send(req, home, method, headers, content, connect, read);

        if (response.status() == HttpURLConnection.HTTP_UNAUTHORIZED && response.headers()
            .containsKey(HttpHeaders.WWW_AUTHENTICATE)) {
            final List<String> wwAuthenticate = response.headers().get(HttpHeaders.WWW_AUTHENTICATE);
            final Map.Entry<String, String> hdr = new AuthHeader(new HeaderTokens(wwAuthenticate), username, password,
                method, req.uri()).header();
            final Collection<Map.Entry<String, String>> hdrs = new LinkedList<>();
            hdrs.add(hdr);
            for (final Map.Entry<String, String> header : headers) {
                hdrs.add(header);
            }
            response = this.origin.send(req, home, method, hdrs, content, connect, read);
        }
        return response;
    }

    private static final class AuthHeader {

        private final Map<String, String> tokens;
        private final String username;
        private final String password;
        private final String method;
        private final RequestURI uri;

        public AuthHeader(final HeaderTokens tokens, final String username, final String password, final String method,
            final RequestURI uri) throws ProtocolException {
            this.tokens = new ValidWwwAuthTokens(tokens).asMap();
            this.username = username;
            this.password = password;
            this.method = method;
            this.uri = uri;
        }

        public Map.Entry<String, String> header() {
            //TODO: implement the whole header
            String value = String.format("Digest username=\"%s\", realm=\"%s\", nonce=\"%s\"");

            return new ImmutableHeader(HttpHeaders.AUTHORIZATION, value);
        }

        private String response() throws NoSuchAlgorithmException {
            final MessageDigest md = md();
            if (hasQop()) {
                md.update(join(hashA1(md), nonce(), nc(), cnonce(), qop(), hashA2(md)));
            } else {
                md.update(join(hashA1(md), nonce(), hashA2(md)));
            }
            return stringify(md.digest());
        }

        private String hashA1(final MessageDigest md) throws NoSuchAlgorithmException {
            md.update(join(username, realm(), password));
            if (md5sess()) {
                md.update(join(stringify(md.digest()), nonce(), cnonce()));
            }
            return stringify(md.digest());
        }

        private String hashA2(final MessageDigest md) throws NoSuchAlgorithmException {
            md.update(join(method, uri.get().getRawPath()));
            return stringify(md.digest());
        }

        private String realm() {
            return tokens.get("realm");
        }

        private String nonce() {
            return tokens.get("nonce");
        }

        private String cnonce() {
            return tokens.get("cnonce");
        }

        private boolean hasCnonce() {
            return tokens.containsKey("cnonce");
        }

        private String nc() {
            return tokens.get("nc");
        }

        private String qop() {
            return tokens.get("qop");
        }

        private boolean hasQop() {
            return tokens.containsKey("qop") && ("auth".equals(tokens.get("qop")) || "auth-int"
                .equals(tokens.get("qop")));
        }

        private MessageDigest md() throws NoSuchAlgorithmException {
            return MessageDigest.getInstance(md5sess() ? "MD5-sess" : "MD5");
        }

        private boolean md5sess() {
            return tokens.containsKey("algorithm") && "md5-sess".equals(tokens.get("algorithm"));
        }

        private boolean opaque() {
            return tokens.containsKey("opaque");
        }

        private static byte[] join(String... values) {
            return StringUtils.join(Arrays.asList(values), ":").getBytes(StandardCharsets.UTF_8);
        }

        private static String stringify(byte[] bytes) {
            return new String(bytes, StandardCharsets.UTF_8);
        }

    }

    private static final class ValidWwwAuthTokens {

        private final HeaderTokens tokens;

        public ValidWwwAuthTokens(final HeaderTokens tokens) {
            this.tokens = tokens;
        }

        public Map<String, String> asMap() throws ProtocolException{
            final Map<String, String> map = tokens.asMap();
            if(map.containsKey("realm") && map.containsKey("nonce")) {
                return map;
            }
            throw new ProtocolException("WwwAuthentication header not valid");
        }
    }

    private static final class HeaderTokens {

        private final List<String> header;

        public HeaderTokens(final List<String> header) {
            this.header = header;
        }

        //TODO: maybe use regex instead of substring abuse
        public Map<String, String> asMap() {
            final Map<String, String> tokens = new HashMap<>();
            for (String token : header.get(0).trim().substring(6).split(",")) {
                //TODO: trim quotes instead of replacing all \"
                tokens.put(token.substring(0, token.indexOf("=")).trim().toLowerCase(),
                    token.substring(token.indexOf("=") + 1).trim().replaceAll("/(?:(?:\r\n)?[ \t])+/g", "")
                        .replaceAll("\"", ""));
            }
            return tokens;
        }
    }
}
