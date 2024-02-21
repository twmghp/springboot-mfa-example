package wm.springbootmfaexample.repository;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.stereotype.Service;

import wm.springbootmfaexample.model.Otp;

@Service
public class OtpRepository {

	private Map<String, Otp> usernameToOtpMap = new HashMap<>();

	public Optional<Otp> getOtpByUsername(String username) {
		return Optional.of(usernameToOtpMap.get(username));
	}

	public void saveOtp(Otp otp) {
		usernameToOtpMap.put(otp.username(), otp);
	}

}
