package wm.springbootmfaexample.security.tokens;

public class TotpMfaToken extends MfaToken {

	private Object principal;

	private String code;

	public TotpMfaToken(Object principal, boolean isAuthenticated) {
		super(true);
		this.principal = principal;
		super.setAuthenticated(isAuthenticated);
	}

	public TotpMfaToken(String code) {
		super(false);
		this.code = code;

	}

	@Override
	public Object getCredentials() {
		return code;
	}

	@Override
	public Object getPrincipal() {
		return principal;
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		this.code = null;
	}

}
