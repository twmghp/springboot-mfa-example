package wm.springbootmfaexample.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import wm.springbootmfaexample.repository.CustomUserRepository;

public class CustomUserDetailsService implements UserDetailsService {

	@Autowired
	private CustomUserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return userRepository.getUserByUsername(username)
			.orElseThrow(() -> new UsernameNotFoundException(username + " not found"));

	}

}
