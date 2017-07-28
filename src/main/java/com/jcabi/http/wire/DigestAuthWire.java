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

        final Response response = this.origin.send(req, home, method, headers, content, connect, read);

        if (response.status() == HttpURLConnection.HTTP_UNAUTHORIZED && response.headers()
            .containsKey(HttpHeaders.WWW_AUTHENTICATE)) {
            final List<String> wwAuthenticate = response.headers().get(HttpHeaders.WWW_AUTHENTICATE);
            Map.Entry<String, String> hdr = new AuthHeader(new WwwAuthHeader(new HeaderTokens(wwAuthenticate)),
                username, password, method, req.uri()).header();
            final Collection<Map.Entry<String, String>> hdrs = new LinkedList<>();
            hdrs.add(hdr);
            for (final Map.Entry<String, String> header : headers) {
                hdrs.add(header);
            }
            return this.origin.send(req, home, method, hdrs, content, connect, read);
        }
        return response;
    }

    private static final class AuthHeader {

        private final WwwAuthHeader header;
        private final String username;
        private final String password;
        private final String method;
        private final RequestURI uri;

        public AuthHeader(final WwwAuthHeader header, final String username, final String password, final String method,
            final RequestURI uri) {
            this.header = header;
            this.username = username;
            this.password = password;
            this.method = method;
            this.uri = uri;
        }

        public Map.Entry<String, String> header() {

            //TODO: construct entire header
            return new ImmutableHeader(HttpHeaders.AUTHORIZATION, "");
        }

        private String response() throws NoSuchAlgorithmException {
            final MessageDigest md = header.md();
            if (header.hasQop()) {
                md.update(join(hashA1(md), header.nonce(), header.nc(), header.cnonce(), header.qop(), hashA2(md)));
            } else {
                md.update(join(hashA1(md), header.nonce(), hashA2(md)));
            }
            return stringify(md.digest());
        }

        private String hashA1(final MessageDigest md) throws NoSuchAlgorithmException {
            md.update(join(username, header.realm(), password));
            if (header.md5sess()) {
                md.update(join(stringify(md.digest()), header.nonce(), header.cnonce()));
            }
            return stringify(md.digest());
        }

        private String hashA2(final MessageDigest md) throws NoSuchAlgorithmException {
            md.update(join(method, uri.get().getRawPath()));
            return stringify(md.digest());
        }

        private static byte[] join(String... values) {
            return StringUtils.join(Arrays.asList(values), ":").getBytes(StandardCharsets.UTF_8);
        }

        private static String stringify(byte[] bytes) {
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    private static final class WwwAuthHeader {

        private final Map<String, String> tokens;

        public WwwAuthHeader(final HeaderTokens tokens) {
            this.tokens = tokens.asMap();
        }

        public String realm() {
            return tokens.get("realm");
        }

        public String nonce() {
            return tokens.get("nonce");
        }

        public String cnonce() {
            return tokens.get("cnonce");
        }

        public boolean hasCnonce() {
            return tokens.containsKey("cnonce");
        }

        public String nc() {
            return tokens.get("nc");
        }

        public String qop() {
            return tokens.get("qop");
        }

        public boolean hasQop() {
            return tokens.containsKey("qop") && ("auth".equals(tokens.get("qop")) || "auth-int"
                .equals(tokens.get("qop")));
        }

        public MessageDigest md() throws NoSuchAlgorithmException {
            return MessageDigest.getInstance(md5sess() ? "MD5-sess" : "MD5");
        }

        public boolean md5sess() {
            return tokens.containsKey("algorithm") && "md5-sess".equals(tokens.get("algorithm"));
        }

        public boolean opaque() {
            return tokens.containsKey("opaque");
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
