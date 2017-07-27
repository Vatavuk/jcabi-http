package com.jcabi.http.wire;

import com.jcabi.http.mock.MkAnswer;
import com.jcabi.http.mock.MkContainer;
import com.jcabi.http.mock.MkGrizzlyContainer;
import com.jcabi.http.request.JdkRequest;
import com.jcabi.http.response.RestResponse;
import org.apache.http.HttpStatus;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.ws.rs.core.HttpHeaders;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.Collection;

/**
 * Test case for {@link DigestAuthWire}.
 *
 * @version $Id$
 * @author Vedran Grgo Vatavuk (123vgv@gmail.com)
 */
@RunWith(Parameterized.class)
public class DigestAuthWireTest {

    /**
     * The username to use for authentication.
     */
    private final transient String username;

    /**
     * The password to use for authentication.
     */
    private final transient String password;

    /**
     * Creates a new test instance for the given username and password
     * combination.
     *
     * @param username The username to user for authentication
     * @param password The password to user for authentication
     */
    public DigestAuthWireTest(final String username, final String password) {
        this.username = username;
        this.password = password;
    }

    /**
     * Test parameters consisting of username and password pairs.
     *
     * @return The username and password parameters used to construct
     *  the test
     */
    @Parameterized.Parameters
    public static Collection<Object[]> getParameters() {
        final Collection<Object[]> parameters = new ArrayList<Object[]>(10);
        parameters.add(new String[] {"Alice", "secret"});
        parameters.add(new String[] {"Bob", "s&e+c`ret"});
        parameters.add(new String[] {"user", "\u20ac\u20ac"});
        return parameters;
    }
    /**
     * Tests if the wire generates the authorization header correctly.
     *
     * @throws Exception If something goes wrong
     */
    @Test
    public void testHeader() throws Exception {
        final MkContainer container = new MkGrizzlyContainer().next(
            new MkAnswer.Simple(HttpStatus.SC_UNAUTHORIZED, "")
                .withHeader(HttpHeaders.WWW_AUTHENTICATE, "Digest realm=\"Members only\", nonce=\"LHOKe1l2BAA=5c373ae0d933a0bb6321125a56a2fcdb6fd7c93b\", "
                    + "algorithm=\"MD5\", qop=\"auth\"/")
        ).start();
        final String expectedHeader = expectHeader(
            this.username,
            this.password
        );
        new JdkRequest(container.home())
            .through(DigestAuthWire.class, username, password)
            .fetch()
            .as(RestResponse.class)
            .assertStatus(HttpURLConnection.HTTP_OK);
        container.stop();
        MatcherAssert.assertThat(
            container.take().headers().get(HttpHeaders.AUTHORIZATION).get(0),
            Matchers.equalTo(expectedHeader)
        );
    }

    /**
     * Creates the expected authorization header value for the
     * given username and password.
     *
     * @param username The username to create the header for
     * @param password The password to create the header for
     * @return The header value in the form
     *  <code>Basic &lt;base64 of username:password&gt;</code>
     */
    private static String expectHeader(final String username,
        final String password) {
        //TODO create full authorization header
        return String.format("Digest username=%s", username);
    }
}
