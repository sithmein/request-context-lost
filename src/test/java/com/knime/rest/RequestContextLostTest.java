package com.knime.rest;

import static io.restassured.RestAssured.given;

import java.net.URL;

import org.apache.http.params.CoreConnectionPNames;
import org.eclipse.jdt.annotation.Nullable;
import org.junit.jupiter.api.Test;

import io.quarkus.test.common.http.TestHTTPEndpoint;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.config.HttpClientConfig;

@QuarkusTest
class RequestContextLostTest {
    @TestHTTPEndpoint(RequestContextLost.class)
    @TestHTTPResource
    @Nullable
    URL m_jobsUrl;

    /**
     * Checks response for a job load timeout.
     */
    @Test
    void testClientHangup() throws Exception {
        var config = RestAssured.config()
            .httpClient(HttpClientConfig.httpClientConfig().setParam(CoreConnectionPNames.SO_TIMEOUT, 1000));

        try {
            given().auth().oauth2(KeycloakAuthTestUtil.USER_ONE.getAccessToken())
                .config(config)
                .queryParam("timeout", "2000").when().post(m_jobsUrl + "/delay")
                .then()//
                .statusCode(200);
        } catch (Exception ex) {
            Thread.sleep(3000);
            throw ex;
        }
    }
}
