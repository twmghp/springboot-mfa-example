package wm.springbootmfaexample.model;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.Getter;

@Getter
public class CustomUser implements UserDetails {

	private static final long serialVersionUID = 1L;

	private String password;

	private String username;

	private boolean accountNonExpired = true;

	private boolean accountNonLocked = true;

	private boolean credentialsNonExpired = true;

	private boolean enabled = true;

	private List<GrantedAuthority> authorities = new ArrayList<>();

	private String totpSecret;

	public CustomUser(String username, String password, String totpSecret) {
		this.username = username;
		this.password = password;
		this.totpSecret = totpSecret;
	}

}
