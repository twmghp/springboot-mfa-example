package wm.springbootmfaexample;

import org.apache.commons.codec.binary.Base32;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.password.PasswordEncoder;

import wm.springbootmfaexample.model.CustomUser;
import wm.springbootmfaexample.repository.CustomUserRepository;

@SpringBootApplication
public class SpringbootMfaExampleApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringbootMfaExampleApplication.class, args);
	}

	@Bean
	CustomUserRepository userRepository(PasswordEncoder passwordEncoder, BytesEncryptor encryptor) {

		String base32Key = "QDWSM3OYBPGTEVSPB5FKVDM3CSNCWHVK";
		Base32 base32 = new Base32();
		String hexSecret = new String(Hex.encode(base32.decode(base32Key)));
		String encrypted = new String(Hex.encode(encryptor.encrypt(hexSecret.getBytes())));
		CustomUser user = new CustomUser("user", passwordEncoder.encode("password"), encrypted);

		CustomUserRepository users = new CustomUserRepository();
		users.addUser(user);
		return users;
	}

}
