package org.bagelcat.scribe.oauth.exception;

/**
 * User: thoand
 * Date: 2011-02-03
 */
public class UserNotAuthorisedException extends Exception {
    public UserNotAuthorisedException(String reason) {
        super(reason);
    }
}
