package org.bagelcat.scribe.oauth.model;

import org.scribe.exceptions.OAuthException;
import org.scribe.model.OAuthConstants;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Verb;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * OAuth request that deals with query-based OAuth-authentication.
 *
 * User: thoand
 * Date: 2011-02-04
 */
public class OAuthQueryStringRequest extends OAuthRequest {

    private final String OAUTH_PREFIX = "oauth_";
    private Map<String, String> queryParams;


    public OAuthQueryStringRequest(Verb verb, String url) {
        super(verb, url);
        this.queryParams = new HashMap<String, String>();

        try {
            // Steal all the parameters from the URL
            String query = new URL(url).getQuery();
            if (query != null) {
                for (String param : query.split("&")) {
                    String pair[] = param.split("=");
                    this.queryParams.put(pair[0], pair[1]);
                }
            }
        } catch (MalformedURLException mfe) {
            throw new OAuthException("Incorrect URL: " + url, mfe);
        }

    }

    /**
     * Add an OAuth-parameter to the query. Note that this required the parameter to start with "oauth_" or an
     * OAuthException is thrown. To add normal parameters, add them to the URL the request is created with.
     *
     * @param key The key. MUST start with "oauth_"
     * @param value The value.
     */
    public void addQueryStringParameter(String key, String value) {
        queryParams.put(checkKey(key), value);
    }

    @Override
    public Response send() {
        try {
            return doSend();
        } catch (IOException ioe) {
            throw new OAuthException("Problems while creating connection", ioe);
        }
    }

    private Response doSend() throws IOException {
        OAuthRequest res = new OAuthRequest(this.getVerb(), getUrl());
        Map<String, String> headers = getHeaders();
        Map<String, String> oauthParams = getOauthParameters();

        for (String key : headers.keySet()) {
            res.addHeader(key, headers.get(key));
        }

        for (String key : oauthParams.keySet()) {
            res.addOAuthParameter(key, oauthParams.get(key));
        }

        String contents = getBodyContents();
        if (contents != null) {
            res.addPayload(getBodyContents());
        }

        return res.send();
    }

    @Override
    public String getUrl() {

        StringBuffer sb = new StringBuffer();
        if (!super.getUrl().contains("?")) {
            sb.append("?");
        }

        for (String key : queryParams.keySet()) {
            sb.append("&").append(key).append("=").append(queryParams.get(key));
        }

        return super.getUrl() + sb.toString();
    }

    @Override
    public Map<String, String> getQueryStringParams() {
        return queryParams;
    }

    private String checkKey(String key) {
        if (!key.startsWith(OAUTH_PREFIX) || key.equals(OAuthConstants.SCOPE)) {
            throw new IllegalArgumentException(String.format("OAuth parameters must either be %s or start with '%s'", OAuthConstants.SCOPE, OAUTH_PREFIX));
        } else {
            return key;
        }
    }
}
