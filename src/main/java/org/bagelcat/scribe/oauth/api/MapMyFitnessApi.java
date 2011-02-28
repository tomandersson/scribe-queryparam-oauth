package org.bagelcat.scribe.oauth.api;

import org.scribe.builder.api.DefaultApi10a;
import org.scribe.model.OAuthConfig;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.oauth.OAuthService;
import org.bagelcat.scribe.oauth.OAuth10aQueryStringServiceImpl;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

/**
 * API implementation for the MapMyFitness OAuth stuff. Note that this makes use of query-based OAuth rather than
 * the standard header-based approach.
 * 
 * User: thoand
 * Date: 2011-02-04
 */
public class MapMyFitnessApi extends DefaultApi10a {

    public static final String AUTHORIZE_URL = "http://api.mapmyfitness.com/3.1/oauth/authorize?oauth_token=%s&oauth_callback=%s";
    private String callback = "";

    @Override
    public String getRequestTokenEndpoint() {
        return "http://api.mapmyfitness.com/3.1/oauth/request_token";
    }

    @Override
    public String getAccessTokenEndpoint() {
        return "http://api.mapmyfitness.com/3.1/oauth/access_token";
    }

    @Override
    public String getAuthorizationUrl(Token requestToken) {
        return String.format(AUTHORIZE_URL, requestToken.getToken(), callback);
    }

    @Override
    public Verb getAccessTokenVerb() {
        return Verb.GET;
    }

    @Override
    public Verb getRequestTokenVerb() {
        return Verb.GET;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public OAuthService createService(OAuthConfig config, String scope) {
        OAuthService service = doCreateService(config);
        service.addScope(scope);

        try {
            callback = URLEncoder.encode(config.getCallback(), "UTF-8");
        } catch (UnsupportedEncodingException uee) {
            // doesn't happen
        }
        return service;
    }

    private OAuthService doCreateService(OAuthConfig config) {
        return new OAuth10aQueryStringServiceImpl(this, config);
    }

}
