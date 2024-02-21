package wm.springbootmfaexample.security.providers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.encrypt.BytesEncryptor;

import wm.springbootmfaexample.model.CustomUser;
import wm.springbootmfaexample.security.tokens.MfaToken;
import wm.springbootmfaexample.security.tokens.OtpMfaToken;
import wm.springbootmfaexample.security.tokens.TotpMfaToken;
import wm.springbootmfaexample.security.tokens.UsernamePasswordMfaToken;
import wm.springbootmfaexample.service.MfaService;

public class MfaProvider implements AuthenticationProvider {

	private final DaoAuthenticationProvider daoAuthenticationProvider;

	private final MfaService mfaService;

	private final BytesEncryptor encryptor;

	@Autowired
	public MfaProvider(DaoAuthenticationProvider daoAuthenticationProvider, MfaService mfaService,
			BytesEncryptor encryptor) {
		this.daoAuthenticationProvider = daoAuthenticationProvider;
		this.mfaService = mfaService;
		this.encryptor = encryptor;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		MfaToken token = (MfaToken) authentication;
		if (token.getClass().isAssignableFrom(UsernamePasswordMfaToken.class)) {
			return authenticateMfaToken((UsernamePasswordMfaToken) token);
		}
		else if (token.getClass().isAssignableFrom(TotpMfaToken.class)) {
			return authenticateMfaToken((TotpMfaToken) token);
		}
		else if (token.getClass().isAssignableFrom(OtpMfaToken.class)) {
			return authenticateMfaToken((OtpMfaToken) token);
		}
		throw new InsufficientAuthenticationException("MultiFactorAuthenticationProvider.authenticate");
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return MfaToken.class.isAssignableFrom(authentication);
	}

	private Authentication authenticateMfaToken(UsernamePasswordMfaToken authentication) {
		Authentication auth = daoAuthenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(
				authentication.getPrincipal(), authentication.getCredentials()));

		if (!auth.isAuthenticated()) {
			throw new BadCredentialsException("MultiFactorAuthenticationProvider.badcredentials");
		}

		return new UsernamePasswordMfaToken(auth.getPrincipal(), false);
	}

	private Authentication authenticateMfaToken(TotpMfaToken authentication) {
		Authentication prevAuthentication = SecurityContextHolder.getContext().getAuthentication();
		MfaToken prevMfaToken = (MfaToken) prevAuthentication;
		checkForValidAuthStage(prevMfaToken, UsernamePasswordMfaToken.class);
		checkIfPreviousAuthIsValid(prevMfaToken);

		String secret;
		try {
			secret = getSecret(prevMfaToken);
		}
		catch (Exception e) {
			throw new InsufficientAuthenticationException("Unable to verify session user");
		}

		if (!this.mfaService.checkTotp(secret, (String) authentication.getCredentials())) {
			throw new BadCredentialsException("MultiFactorAuthenticationProvider.badcredentials");
		}

		return new TotpMfaToken(prevAuthentication.getPrincipal(), false);
	}

	private Authentication authenticateMfaToken(OtpMfaToken authentication) {
		Authentication prevAuthentication = SecurityContextHolder.getContext().getAuthentication();

		MfaToken prevMfaToken = (MfaToken) prevAuthentication;
		checkForValidAuthStage(prevMfaToken, TotpMfaToken.class);
		checkIfPreviousAuthIsValid(prevMfaToken);

		if (!this.mfaService.checkOtp((CustomUser) prevMfaToken.getPrincipal(),
				(String) authentication.getCredentials())) {
			throw new BadCredentialsException("MultiFactorAuthenticationProvider.badcredentials");
		}

		return new OtpMfaToken(prevAuthentication.getPrincipal(), true);
	}

	private void checkIfPreviousAuthIsValid(MfaToken prevToken) throws InsufficientAuthenticationException {
		if (!prevToken.isStageAuthenticated()) {
			throw new InsufficientAuthenticationException(
					"MultiFactorAuthenticationProvider.InsufficientAuthenticationException previous stage not authenticated");
		}
	}

	private void checkForValidAuthStage(MfaToken prevToken, Class<? extends MfaToken> clazz) {
		if (!prevToken.getClass().isAssignableFrom(clazz)) {
			throw new InsufficientAuthenticationException(
					"MultiFactorAuthenticationProvider.InsufficientAuthenticationException out of order authentication");
		}
	}

	private String getSecret(MfaToken authentication) throws Exception {
		if (authentication.getPrincipal() instanceof CustomUser) {
			CustomUser user = (CustomUser) authentication.getPrincipal();
			byte[] bytes = Hex.decode(user.getTotpSecret());
			return new String(this.encryptor.decrypt(bytes));
		}
		return "";
	}

}
