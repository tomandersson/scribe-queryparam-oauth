package org.bagelcat.scribe.oauth;

import org.scribe.builder.api.DefaultApi10a;
import org.scribe.model.OAuthConfig;
import org.scribe.model.OAuthConstants;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Token;
import org.scribe.oauth.OAuth10aServiceImpl;
import org.bagelcat.scribe.oauth.model.OAuthQueryStringRequest;

/**
 * Service for dealing with OAuth providers that require the authentication parameters to reside in the URI's
 * query parameters. This should only be used when the more common header-variety isn't available. Twitter's OAuth
 * page has this to say:
 *
 * "Twitter prefers header-based auth because it separates concerns, makes debugging easier, and avoids common issues
 * with under or over URL escaping parameters. [...] Go for the gold. Go for header-based OAuth."
 *
 * User: thoand
 * Date: 2011-02-04
 */
public class OAuth10aQueryStringServiceImpl extends OAuth10aServiceImpl {

    DefaultApi10a api;
    OAuthConfig config;

    public OAuth10aQueryStringServiceImpl(DefaultApi10a api, OAuthConfig config) {
        super(api, config);

        this.config = config;
        this.api = api;
    }

    public void signRequest(Token token, OAuthQueryStringRequest request) {
        // We need to get the Header-version too, or the Scribe-lib's verification will fail
        super.signRequest(token, request);

        // Add everything but the callback
        request.addQueryStringParameter(OAuthConstants.TOKEN, token.getToken());
        request.addQueryStringParameter(OAuthConstants.TIMESTAMP, api.getTimestampService().getTimestampInSeconds());
        request.addQueryStringParameter(OAuthConstants.NONCE, api.getTimestampService().getNonce());
        request.addQueryStringParameter(OAuthConstants.CONSUMER_KEY, config.getApiKey());
        request.addQueryStringParameter(OAuthConstants.SIGN_METHOD, api.getSignatureService().getSignatureMethod());
        request.addQueryStringParameter(OAuthConstants.VERSION, getVersion());
        request.addQueryStringParameter(OAuthConstants.SIGNATURE, getSignature(request, token));

    }

    private String getSignature(OAuthRequest request, Token token) {
        String baseString = api.getBaseStringExtractor().extract(request);
        return api.getSignatureService().getSignature(baseString, config.getApiSecret(), token.getSecret());
    }
}
