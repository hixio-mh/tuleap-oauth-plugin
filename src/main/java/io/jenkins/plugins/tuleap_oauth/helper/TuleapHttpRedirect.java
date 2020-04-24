package io.jenkins.plugins.tuleap_oauth.helper;

import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

import javax.servlet.ServletException;
import java.io.IOException;

public final class TuleapHttpRedirect extends RuntimeException implements HttpResponse {
    private final int statusCode;
    private final String url;

    public TuleapHttpRedirect(String url) {
        if (url == null) {
            throw new NullPointerException();
        }
        this.url = url;
        this.statusCode = 302;
    }

    public String getUrl() {
        return this.url;
    }

    @Override
    public void generateResponse(StaplerRequest staplerRequest, StaplerResponse staplerResponse, Object o) throws IOException, ServletException {
        staplerResponse.sendRedirect(this.statusCode, this.url);
    }
}
