package com.knime.rest;

import io.quarkus.vertx.web.RouteFilter;
import io.vertx.ext.web.RoutingContext;

public class CSRFFilter {
    @RouteFilter // <== Removing this makes the problem disappear
    void checkForCSRF(final RoutingContext rc) {
        rc.next();
    }
}
