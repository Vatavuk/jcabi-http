package com.jcabi.http.wire;

import com.jcabi.aspects.Immutable;
import com.jcabi.http.ImmutableHeader;
import com.jcabi.http.Request;
import com.jcabi.http.Response;
import com.jcabi.http.Wire;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import javax.ws.rs.core.HttpHeaders;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

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
            Map.Entry<String, String> hdr = new AuthorizationHeader(
                new AuthenticationHeader(response.headers().get(HttpHeaders.WWW_AUTHENTICATE)), username, password)
                .header();
            final Collection<Map.Entry<String, String>> hdrs = new LinkedList<>();
            hdrs.add(hdr);
            for (final Map.Entry<String, String> header : headers) {
                hdrs.add(header);
            }
            return this.origin.send(req, home, method, hdrs, content, connect, read);
        }

        return response;
    }

    private static final class AuthorizationHeader {

        private final AuthenticationHeader header;
        private final String username;
        private final String password;

        public AuthorizationHeader(final AuthenticationHeader header, final String username, final String password) {
            this.header = header;
            this.username = username;
            this.password = password;
        }

        public Map.Entry<String, String> header() {
            //TODO: build entire header
            return new ImmutableHeader(HttpHeaders.AUTHORIZATION, "");
        }
    }

    private static final class AuthenticationHeader {

        private final ImmutableHeader header;

        public AuthenticationHeader(final List<String> header) {
            this.header = new ImmutableHeader(HttpHeaders.WWW_AUTHENTICATE, header.get(0));
        }

        public String algorithm() {
            //TODO: return algorithm part from header
            return "";
        }

        private static String unq(String value) {
            //TODO: extract value from header
            return "";
        }

    }
}
