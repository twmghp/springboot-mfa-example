package wm.springbootmfaexample.security.tokens;

public class UsernamePasswordMfaToken extends MfaToken {

	private Object principal;

	private Object credentials;

	public UsernamePasswordMfaToken(Object username, Object password) {
		super(false);
		this.principal = username;
		this.credentials = password;
	}

	public UsernamePasswordMfaToken(Object principal, boolean isAuthenticated) {
		super(true);
		super.setAuthenticated(isAuthenticated);
		this.principal = principal;

	}

	@Override
	public Object getCredentials() {
		return this.credentials;
	}

	@Override
	public Object getPrincipal() {
		// TODO Auto-generated method stub
		return principal;
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		this.credentials = null;
	}

}
