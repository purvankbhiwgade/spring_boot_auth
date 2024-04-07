package grand.project.users.services;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import grand.project.users.repository.UserRepository;

// This implementation is typically configured as a bean and injected into Spring Security's DaoAuthenticationProvider
// By integrating with the UserDetailsService, Spring Security can leverage your 
// application's existing user storage mechanism (database, LDAP, etc.) for authentication purposes, 
// without directly interacting with the data source itself.
@Service
public class UserService implements UserDetailsService {

	private PasswordEncoder encoder;

	private UserRepository userRepository;

	public UserService(PasswordEncoder encoder, UserRepository userRepository) {
		super();
		this.encoder = encoder;
		this.userRepository = userRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		System.out.println("In the user details service");
 
		// ---------------- Hardcoding username and their password
		// -------------------------
//		if(!username.equals("Ethan")) throw new UsernameNotFoundException("Not Ethan");
//		
//		Set<Role> roles = new HashSet<>();
//		roles.add(new Role(1, "USER"));
//		return new ApplicationUser(1, "Ethan", encoder.encode("password"),roles);

//		-------------- Varied Username and password, by default it supports (admin/password) as (username/password)
		return userRepository.findByUsername(username)
				.orElseThrow(() -> new UsernameNotFoundException("user is not valid"));

	}

}
