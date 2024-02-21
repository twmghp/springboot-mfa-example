package wm.springbootmfaexample.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.encrypt.AesBytesEncryptor;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import wm.springbootmfaexample.security.filters.OtpMfaFilter;
import wm.springbootmfaexample.security.filters.TotpMfaFilter;
import wm.springbootmfaexample.security.filters.UsernamePasswordMfaFilter;
import wm.springbootmfaexample.security.handlers.GenOtpSuccessHandler;
import wm.springbootmfaexample.security.handlers.RestrictMfaAttemptsHandler;
import wm.springbootmfaexample.security.providers.MfaProvider;
import wm.springbootmfaexample.security.tokens.MfaToken;
import wm.springbootmfaexample.service.CustomUserDetailsService;
import wm.springbootmfaexample.service.MfaService;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Value("${multifactorauth.max-attempts:3}")
	private int MAX_ATTEMPTS;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http,
			UsernamePasswordMfaFilter usernamePasswordMfaFilter, TotpMfaFilter totpMfaFilter, OtpMfaFilter otpMfaFilter,
			AuthorizationManager<RequestAuthorizationContext> mfaAuthorizationManager) throws Exception {

		// @formatter:off
		http
			.csrf(csrf-> csrf.disable())
			.addFilterAt(usernamePasswordMfaFilter, UsernamePasswordAuthenticationFilter.class)
			.addFilterAfter(totpMfaFilter, UsernamePasswordAuthenticationFilter.class)
			.addFilterAfter(otpMfaFilter, TotpMfaFilter.class)
			.authorizeHttpRequests(authorize-> authorize
				.requestMatchers("login").permitAll()
				.requestMatchers("/totp", "/otp", "otp/new").access(mfaAuthorizationManager)
				.anyRequest().authenticated()
			);
		// @formatter:on
		return http.build();
	}

	@Bean
	public AuthenticationManager authenticationManager(UserDetailsService userDetailsService,
			PasswordEncoder passwordEncoder, MfaService mfaService, BytesEncryptor bytesEncryptor) {
		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
		daoAuthenticationProvider.setUserDetailsService(userDetailsService);
		daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
		MfaProvider multiFactorAuthenticationProvider = new MfaProvider(daoAuthenticationProvider, mfaService,
				bytesEncryptor);
		return new ProviderManager(daoAuthenticationProvider, multiFactorAuthenticationProvider);
	}

	@Bean
	AuthorizationManager<RequestAuthorizationContext> mfaAuthorizationManager() {
		return (authentication, context) -> new AuthorizationDecision(
				authentication.get() instanceof MfaToken && !authentication.get().isAuthenticated());
	}

	@Bean
	public UsernamePasswordMfaFilter usernamePasswordMfaFilter(AuthenticationManager authenticationManager) {
		UsernamePasswordMfaFilter authFilter = new UsernamePasswordMfaFilter();
		authFilter.setAuthenticationManager(authenticationManager);
		authFilter.setSecurityContextRepository(securityContextRepository());
		authFilter.setSessionAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
		authFilter.setAuthenticationSuccessHandler((req, res, auth) -> {
			res.setStatus(HttpStatus.OK.value());
		});
		authFilter.setAuthenticationFailureHandler((req, res, auth) -> {
			res.setStatus(HttpStatus.FORBIDDEN.value());
		});

		return authFilter;
	}

	@Bean
	public TotpMfaFilter totpMfaFilter(AuthenticationManager authenticationManager, MfaService mfaService) {
		TotpMfaFilter authFilter = new TotpMfaFilter();
		authFilter.setAuthenticationManager(authenticationManager);
		authFilter.setSecurityContextRepository(securityContextRepository());
		authFilter.setSessionAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());

		// Success handlers
		RestrictMfaAttemptsHandler restrictMfaAttemptHandler = new RestrictMfaAttemptsHandler(MAX_ATTEMPTS);
		GenOtpSuccessHandler genOtpSuccessHandler = new GenOtpSuccessHandler(mfaService);
		authFilter.setAuthenticationSuccessHandler((req, res, auth) -> {
			restrictMfaAttemptHandler.onAuthenticationSuccess(req, res, auth);
			genOtpSuccessHandler.onAuthenticationSuccess(req, res, auth);
		});
		// Failure handlers
		authFilter.setAuthenticationFailureHandler(restrictMfaAttemptHandler);
		return authFilter;
	}

	@Bean
	public OtpMfaFilter otpMfaFilter(AuthenticationManager authenticationManager) {
		OtpMfaFilter authFilter = new OtpMfaFilter();
		authFilter.setAuthenticationManager(authenticationManager);
		authFilter.setSecurityContextRepository(securityContextRepository());
		authFilter.setSessionAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
		RestrictMfaAttemptsHandler restrictMfaAttemptHandler = new RestrictMfaAttemptsHandler(MAX_ATTEMPTS);
		// Success handlers
		authFilter.setAuthenticationSuccessHandler(restrictMfaAttemptHandler);
		// Failure handlers
		authFilter.setAuthenticationFailureHandler(restrictMfaAttemptHandler);
		return authFilter;
	}

	@Bean
	public AuthenticationFailureHandler defaultAuthFailureHandler() {
		return new AuthenticationFailureHandler() {

			@Override
			public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
					AuthenticationException exception) throws IOException, ServletException {
				response.setStatus(HttpStatus.BAD_GATEWAY.value());
			}
		};
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public UserDetailsService customUserDetailsService() {
		return new CustomUserDetailsService();
	}

	@Bean
	public SecurityContextRepository securityContextRepository() {
		return new DelegatingSecurityContextRepository(new HttpSessionSecurityContextRepository());
	}

	@Bean
	AesBytesEncryptor encryptor() throws Exception {
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		generator.init(128);
		SecretKey key = generator.generateKey();
		return new AesBytesEncryptor(key, KeyGenerators.secureRandom(12), AesBytesEncryptor.CipherAlgorithm.GCM);
	}

}
