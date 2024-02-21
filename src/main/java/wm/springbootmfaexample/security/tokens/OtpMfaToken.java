package wm.springbootmfaexample.security.tokens;

public class OtpMfaToken extends MfaToken {

	private String code;

	private Object principal;

	public OtpMfaToken(String code) {
		super(false);
		this.code = code;
	}

	public OtpMfaToken(Object principal, boolean isAuthenticated) {
		super(true);
		super.setAuthenticated(isAuthenticated);
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
