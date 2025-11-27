package com.knime.rest;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static java.util.stream.Collectors.joining;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.http.HttpHeaders;
import org.apache.http.entity.ContentType;
import org.eclipse.jdt.annotation.Nullable;
import org.jboss.logging.Logger;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.knime.rest.KeycloakAuthTestUtil.User;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import io.smallrye.jwt.util.ResourceUtils;

public class KeycloakWiremockTestResource implements QuarkusTestResourceLifecycleManager {

    private static final Logger LOGGER = Logger.getLogger(KeycloakWiremockTestResource.class);

    @Nullable
    private WireMockServer m_server;

    @Override
    public Map<String, @Nullable String> start() {
        final var server =
            new WireMockServer(wireMockConfig().dynamicPort());
        server.start();

        server.stubFor(get(urlEqualTo("/auth/realms/knime/.well-known/openid-configuration")).willReturn(aResponse()
            .withHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType())
            .withBody("{\n" + "    \"jwks_uri\": \"" + server.baseUrl()
                + "/auth/realms/knime/protocol/openid-connect/certs\",\n" + "    \"token_introspection_endpoint\": \""
                + server.baseUrl() + "/auth/realms/knime/protocol/openid-connect/token/introspect\",\n"
                + "    \"authorization_endpoint\": \"" + server.baseUrl() + "/auth/realms/knime\","
                + "    \"token_endpoint\": \"" + server.baseUrl() + "/auth/realms/knime/token\","
                + "    \"issuer\" : \"" + KeycloakAuthTestUtil.TOKEN_ISSUER + "\","
                + "    \"introspection_endpoint\": \"" + server.baseUrl()
                + "/auth/realms/knime/protocol/openid-connect/token/introspect\"" + "}")));

        try {
            final var publicKey = ResourceUtils.readResource(KeycloakAuthTestUtil.JWK_LOCATION);
            server.stubFor(get(urlEqualTo(KeycloakAuthTestUtil.JWKS_ENDPOINT)).willReturn(aResponse()
                .withHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType())
                .withBody("{\n" + "  \"keys\" : [\n" + "    " + publicKey + "\n" + "  ]\n" + "}")));

        } catch (IOException ex) {
            throw new IllegalStateException(
                "JWK could not be read from default location " + KeycloakAuthTestUtil.JWK_LOCATION, ex);
        }


        // define the mock for the introspect endpoint

        addUser(KeycloakAuthTestUtil.USER_ONE, server);

        // Login Page
        server.stubFor(get(urlPathMatching("/auth/realms/knime")).willReturn(aResponse()
            .withHeader(HttpHeaders.CONTENT_TYPE, "text/html")
            .withBody("""
                <html>
                <body>
                  <form action="/login" name="form">
                    <input type="text" id="username" name="username"/>
                    <input type="password" id="password" name="password"/>
                    <input type="hidden" id="state" name="state" value="{{request.query.state}}"/>
                    <input type="hidden" id="redirect_uri" name="redirect_uri" value="{{request.query.redirect_uri}}"/>
                    <input type="submit" id="login" value="login"/>
                  </form>
                </body>
                </html>
                """)
            .withTransformers("response-template")));

        // Login Request
        server.stubFor(get(urlPathMatching("/login")).willReturn(aResponse().withHeader("Location",
            "{{request.query.redirect_uri}}?state={{request.query.state}}&code=58af24f2-9093-4674-a431-4a9d66be719c."
                + "50437113-cd78-48a2-838e-b936fe458c5d.0ac5df91-e044-4051-bd03-106a3a5fb9cc")
            .withStatus(302).withTransformers("response-template")));

        LOGGER.infof("Keycloak started in mock mode: %s", server.baseUrl());
        var conf = new HashMap<String, @Nullable String>();
        // Configuration parameters for quarkus-oidc
        conf.put("quarkus.oidc.auth-server-url", server.baseUrl() + "/auth/realms/knime");
        conf.put("quarkus.oidc-client.auth-server-url", server.baseUrl() + "/auth/realms/knime");
        conf.put("quarkus.oidc.code-flow.auth-server-url", server.baseUrl() + "/auth/realms/knime");
        conf.put("keycloak-url", server.baseUrl());
        // Configuration parameters for smallrye-jwt
        conf.put("mp.jwt.verify.publickey.location", server.baseUrl() + KeycloakAuthTestUtil.JWKS_ENDPOINT);
        conf.put("mp.jwt.verify.issuer", KeycloakAuthTestUtil.TOKEN_ISSUER);
        conf.put("mp.jwt.verify.publickey.algorithm", KeycloakAuthTestUtil.KEY_ALG.getAlgorithm());

        m_server = server;
        return conf;
    }

    private static void addUser(final User user, final WireMockServer server) {
        defineValidIntrospectionMockTokenStubForUserWithRoles(user.m_username, user.m_jwtGroups, server);
    }

    private static void defineValidIntrospectionMockTokenStubForUserWithRoles(final String user,
        final Set<String> roles, final WireMockServer server) {
        server.stubFor(WireMock.post("/auth/realms/knime/protocol/openid-connect/token/introspect")
            .withRequestBody(matching("token=" + user + "&token_type_hint=access_token"))
            .willReturn(WireMock.aResponse()
                .withHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType())
                .withBody("{\"active\":true,\"scope\":\"" + roles.stream().collect(joining(" ")) + "\",\"username\":\""
                    + user + "\",\"iat\":1,\"exp\":999999999999,\"expires_in\":999999999999,"
                    + "\"client_id\":\"my_client_id\"}")));
    }

    @Override
    public synchronized void stop() {
        var server = m_server;
        if (server != null) {
            server.stop();
            LOGGER.info("Keycloak was shut down");
            server.resetAll();
        }
    }
}
