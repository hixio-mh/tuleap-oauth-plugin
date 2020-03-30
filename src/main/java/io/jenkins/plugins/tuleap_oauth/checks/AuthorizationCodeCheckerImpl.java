package io.jenkins.plugins.tuleap_oauth.checks;

import io.jenkins.plugins.tuleap_oauth.TuleapSecurityRealm;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.StaplerRequest;

import java.util.logging.Level;
import java.util.logging.Logger;

public class AuthorizationCodeCheckerImpl implements AuthorizationCodeChecker {
    private static Logger LOGGER = Logger.getLogger(AuthorizationCodeCheckerImpl.class.getName());

    public boolean checkAuthorizationCode(StaplerRequest request) {
        final String code = request.getParameter("code");

        if (StringUtils.isBlank(code)) {
            LOGGER.log(Level.WARNING, "no code returned");
            return false;
        }

        final String state = request.getParameter("state");
        final String expectedState = (String) request.getSession().getAttribute(TuleapSecurityRealm.STATE_SESSION_ATTRIBUTE);

        if (StringUtils.isBlank(state)) {
            LOGGER.log(Level.WARNING, "no state returned");
            return false;
        }

        if (StringUtils.isBlank(expectedState)) {
            LOGGER.log(Level.WARNING, "no state saved from user's session");
            return false;
        }

        if (!state.equals(expectedState)) {
            LOGGER.log(Level.WARNING, "expected state and provided state does not match");
            return false;
        }

        final String codeVerifier = (String) request.getSession().getAttribute(TuleapSecurityRealm.CODE_VERIFIER_SESSION_ATTRIBUTE);
        if (StringUtils.isBlank(codeVerifier)) {
            LOGGER.log(Level.WARNING, "no code verifier saved from user's session");
            return false;
        }

        return true;
    }
}
