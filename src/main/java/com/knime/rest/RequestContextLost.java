package com.knime.rest;

import io.quarkus.security.Authenticated;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/context-lost")
@Authenticated // <== Removing this makes the problem disappear
public class RequestContextLost {
    @Context
    HttpHeaders m_requestHeaders;

    @POST
    @Consumes("*/*")
    @Produces(MediaType.APPLICATION_JSON)
    @Path("delay")
    public Response delay(@QueryParam("timeout") @DefaultValue("-1") final long timeout) throws Exception {
        Thread.sleep(timeout);
        m_requestHeaders.getDate();
        return Response.ok().build();
    }
}
