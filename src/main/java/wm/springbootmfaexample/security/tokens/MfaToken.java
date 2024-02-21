package wm.springbootmfaexample.security.tokens;

import org.springframework.security.authentication.AbstractAuthenticationToken;

public abstract class MfaToken extends AbstractAuthenticationToken {

	private boolean isStageAuthenticated;

	public MfaToken(boolean isStageAuthenticated) {
		super(null);
		this.isStageAuthenticated = isStageAuthenticated;
	}

	public boolean isStageAuthenticated() {
		return isStageAuthenticated;
	}

}
