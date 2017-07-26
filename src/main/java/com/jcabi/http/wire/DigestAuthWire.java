package com.jcabi.http.wire;

import com.jcabi.aspects.Immutable;
import com.jcabi.http.Request;
import com.jcabi.http.Response;
import com.jcabi.http.Wire;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.Map;

/**
 * Wire with HTTP digest authentication based on provided user credentials.
 *
 * <p>This wire converts user info from URI into
 * {@code "Authorization"} HTTP header, for example:
 *
 * <pre> String html = new JdkRequest("http://jeff:12345@example.com")
 *   .through(BasicAuthWire.class)
 *   .fetch()
 *   .body();</pre>
 *
 * <p>In this example, an additional HTTP header {@code Authorization}
 * will be added with a value {@code Basic amVmZjoxMjM0NQ==}.
 *
 * <p>The class is immutable and thread-safe.
 *
 * @author Vedran Grgo Vatavuk (123vgv@gmail.com)
 * @version $Id$
 * @since 0.10
 * @see <a href="http://tools.ietf.org/html/rfc2617">RFC 2617 "HTTP Authentication: Basic and Digest Access Authentication"</a>
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

    public DigestAuthWire(final Wire origin, final  String username, final String password) {
        this.origin = origin;
        this.username = username;
        this.password = password;
    }

    @Override
    public Response send(final Request req, final String home, final String method, final Collection<Map.Entry<String, String>> headers,
        final InputStream content, final int connect, final int read) throws IOException {
        return null;
    }
}
