package com.knime.rest;

import static java.lang.System.getProperty;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.time.Duration;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.microprofile.jwt.Claims;

import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.util.KeyUtils;
import io.smallrye.jwt.util.ResourceUtils;

public final class KeycloakAuthTestUtil {

    private static final String KNIME_JWT_GROUP = "knime";

    private static final String HUBUSER_JWT_GROUP = "hubuser";

    /**
     * The token audience used for tests.
     */
    public static final String TOKEN_AUDIENCE = "audience";

    /**
     * The private key location used signing of JWTs during tests.
     */
    public static final String PRIVATE_KEY_LOCATION = "classpath:test/pkcs8-keycloak-privateKey.pem";

    /**
     * The public key location used for validation of JWTs during tests.
     */
    public static final String JWK_LOCATION = "classpath:test/keycloak-publicKey.jwk";

    /**
     * The public key with which JWT created by this class can be verified.
     */
    public static final PublicKey PUBLIC_KEY;

    /**
     * The key id that should be used for the JWTs during tests.
     */
    public static final String KEY_ID = "UydhRuzrsP1FeYIf2_n3GpVvl78SpLd3jjX0Ijgp7AY";

    /**
     * THe key algorithm used for the JWTs during tests.
     */
    public static final SignatureAlgorithm KEY_ALG = SignatureAlgorithm.RS256;

    /**
     * The token endpoint used for tests.
     */
    public static final String TOKEN_ENDPOINT = "/auth/realms/KNIME/protocol/openid-connect/token";

    /**
     * The JWKS endpoint for tests.
     */
    public static final String JWKS_ENDPOINT = "/auth/realms/KNIME/protocol/openid-connect/certs";

    /**
     * The token issuer used for tests
     */
    @Nullable
    public static final String TOKEN_ISSUER =
        getProperty("quarkus.test.oidc.token.issuer", "https://keycloak.knime.com");

    /**
     * The token expiration.
     */
    public static final Duration TOKEN_EXPIRATION = Duration.ofMinutes(30);

    /**
     * User one.
     */
    public static final User USER_ONE = new User("knime-one", "account:user:11111111-1111-1111-1111-111111111111",
        Set.of(KNIME_JWT_GROUP, HUBUSER_JWT_GROUP, "firstUserGroup"), "KNIME One");

    static {
        try {
            var publicKey = ResourceUtils.readResource("classpath:test/pkcs8-keycloak-publicKey.pem");
            PUBLIC_KEY = KeyUtils.decodeEncryptionPublicKey(publicKey, KeyEncryptionAlgorithm.RSA_OAEP_256);
        } catch (GeneralSecurityException | IOException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private KeycloakAuthTestUtil() {
        // empty
    }

    /**
     * Returns the access token for the given user.
     *
     * <p>
     * This method should only be used to create tokens that mimic a user change in Keycloak. Otherwise the
     * {@link User#getAccessToken()} should be used.
     * </p>
     *
     * @param user the user
     * @param additionalCustomClaims a map with custom claims, the key being the claim name, and the value being the
     *            claim value
     * @return the access token
     */
    public static String getAccessToken(final User user, final Map<String, Object> additionalCustomClaims) {
        var jwtBuilder = Jwt.preferredUserName(user.m_username)//
            .groups(user.m_jwtGroups)//
            .issuer(TOKEN_ISSUER)//
            .audience(TOKEN_AUDIENCE)//
            .subject(StringUtils.substringAfterLast(user.m_id, ":"))//
            .expiresIn(TOKEN_EXPIRATION)//
            .claim(Claims.email.name(), user.m_mail)//
            .claim(Claims.email_verified.name(), true)//
            .claim("name", user.m_realName);

        additionalCustomClaims.entrySet().stream().forEach(e -> jwtBuilder.claim(e.getKey(), e.getValue()));

        return jwtBuilder.jws().keyId(KEY_ID).sign(PRIVATE_KEY_LOCATION);
    }

    /**
     * Class representing a user with all necessary fields.
     */
    public static final class User {

        /**
         * The username.
         */
        public final String m_username;

        /**
         * The id.
         */
        public final String m_id;

        /**
         * The mail address.
         */
        public final String m_mail;

        /**
         * The user's real name (<tt>name</tt> claim in the JWT).
         */
        public final String m_realName;

        /**
         * The JWT groups.
         */
        public final Set<String> m_jwtGroups;

        private final boolean m_isAnonymous;

        /**
         * Creates a new user representation.
         *
         * @param username the username
         * @param id the id
         * @param jwtGroups the JWT groups
         * @param realName the user's real name
         */
        public User(final String username, final String id, final Set<String> jwtGroups, final String realName) {
            this(username, id, username + "@knimemail", jwtGroups, realName);
        }

        /**
         * Creates a new user representation.
         *
         * @param username the username
         * @param id the id
         * @param mail the email address
         * @param realName the user's real name
         * @param jwtGroups the JWT groups
         */
        public User(final String username, final String id, final String mail, final Set<String> jwtGroups,
            final String realName) {
            this(username, id, mail, jwtGroups, realName, false);
        }

        /**
         * Creates a new user representation.
         *
         * @param username the username
         * @param id the id
         * @param mail the email address
         * @param jwtGroups the JWT groups
         * @param realName the user's real name
         * @param isAnonymous <code>true</code> if the user is an anonymous user, <code>false</code> otherwise
         */
        private User(final String username, final String id, final String mail, final Set<String> jwtGroups,
            final String realName, final boolean isAnonymous) {
            m_username = username;
            m_id = id;
            m_mail = mail;
            m_realName = realName;
            // Needs to be a HashSet due to an issue with modifiable sets when providing a user via @MethodSource
            // see https://github.com/quarkusio/quarkus/issues/24492
            m_jwtGroups = new HashSet<>(jwtGroups);
            m_isAnonymous = isAnonymous;
        }

        /**
         * Generates an access token for the user.
         *
         * @return the access token
         */
        public String getAccessToken() {
            return m_isAnonymous ? "" : KeycloakAuthTestUtil.getAccessToken(this, Map.of());
        }

        @Override
        public int hashCode() {
            return Objects.hash(m_id, m_jwtGroups, m_mail, m_username);
        }

        @Override
        public boolean equals(@Nullable final Object obj) {
            if ((obj == null) || (getClass() != obj.getClass())) {
                return false;
            }

            var other = (User)obj;
            return Objects.equals(m_id, other.m_id) && Objects.equals(m_jwtGroups, other.m_jwtGroups)
                && Objects.equals(m_mail, other.m_mail) && Objects.equals(m_username, other.m_username);
        }
    }
}
