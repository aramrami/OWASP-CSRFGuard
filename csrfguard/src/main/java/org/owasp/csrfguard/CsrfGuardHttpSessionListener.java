package org.owasp.csrfguard;

import org.owasp.csrfguard.util.SessionUtils;

import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

public class CsrfGuardHttpSessionListener implements HttpSessionListener {

    @Override
    public void sessionCreated(HttpSessionEvent event) {
        HttpSession session = event.getSession();
        CsrfGuard csrfGuard = CsrfGuard.getInstance();
        csrfGuard.updateToken(session);
        // Check if should generate tokens for protected resources on current session
        if (csrfGuard.isTokenPerPageEnabled() && csrfGuard.isTokenPerPagePrecreate()
                && !SessionUtils.tokensGenerated(session)) {
            csrfGuard.generatePageTokensForSession(session);
        }

    }

    @Override
    public void sessionDestroyed(HttpSessionEvent event) {
        /** nothing to do **/
    }

}
