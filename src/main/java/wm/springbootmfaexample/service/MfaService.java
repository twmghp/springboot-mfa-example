package wm.springbootmfaexample.service;

import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;

import wm.springbootmfaexample.model.CustomUser;
import wm.springbootmfaexample.model.Otp;
import wm.springbootmfaexample.repository.OtpRepository;

@Service
public class MfaService {

	@Value("${multifactorauth.otp.timeout-sec:5}")
	private int OTP_TIMEOUT_SECONDS;

	private OtpRepository otpRepository;

	public MfaService(OtpRepository otpRepository) {
		this.otpRepository = otpRepository;
	}

	public boolean checkTotp(String hexKey, String code) {
		try {
			return TimeBasedOneTimePasswordUtil.validateCurrentNumberHex(hexKey, Integer.parseInt(code), 10000);
		}
		catch (GeneralSecurityException ex) {
			throw new IllegalArgumentException(ex);
		}
	}

	public boolean checkOtp(CustomUser user, String code) {
		Optional<Otp> otpOptional = otpRepository.getOtpByUsername(user.getUsername());
		if (otpOptional.isEmpty()) {
			return false;
		}
		Otp otp = otpOptional.get();
		Duration duration = Duration.between(otp.genTimestamp(), Instant.now());
		return otp.value().equals(code) && duration.getSeconds() < OTP_TIMEOUT_SECONDS;
	}

	public String generateOtp(CustomUser user) {
		String code = "123456";
		otpRepository.saveOtp(new Otp(user.getUsername(), code, Instant.now()));
		return code;
	}

}
