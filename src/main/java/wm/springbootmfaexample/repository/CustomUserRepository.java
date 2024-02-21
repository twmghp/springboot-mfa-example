package wm.springbootmfaexample.repository;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.stereotype.Service;

import wm.springbootmfaexample.model.CustomUser;

@Service
public class CustomUserRepository {

	private Map<String, CustomUser> users = new HashMap<>();

	public void addUser(CustomUser user) {
		users.put(user.getUsername(), user);
	}

	public Optional<CustomUser> getUserByUsername(String username) {
		if (users.containsKey(username)) {
			return Optional.of(users.get(username));
		}
		return Optional.empty();
	}

}
