package grand.project.users.services;

import java.util.HashSet;
import java.util.Set;

import javax.naming.AuthenticationException;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import grand.project.users.models.ApplicationUser;
import grand.project.users.models.LoginResponseDTO;
import grand.project.users.models.Role;
import grand.project.users.repository.RoleRepository;
import grand.project.users.repository.UserRepository;

@Service // creates a bean first
@Transactional  //  converts each method under this class as ONE TRANSACTION - so that in case a method contains a lot of queries and it fails - it cancels out the whole method (ie. the whole transaction)
public class AuthenticationService {
	
	private UserRepository userRepository;
	
	private RoleRepository roleRepository;
	
	private PasswordEncoder passwordEncoder;
	
	private AuthenticationManager authenticationManager;
	
	private TokenService tokenService;
	
	public AuthenticationService(UserRepository userRepository, RoleRepository roleRepository,
			PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, TokenService tokenService) {
		super();
		this.userRepository = userRepository;
		this.roleRepository = roleRepository;
		this.passwordEncoder = passwordEncoder;
		this.authenticationManager = authenticationManager;
		this.tokenService = tokenService;
	}

	public ApplicationUser registerUser(String username, String password) {
		
		String encodedPassword = passwordEncoder.encode(password);
		Role userRole = roleRepository.findByAuthority("USER").get();
		
		Set<Role> authorities = new HashSet<>();
		
		authorities.add(userRole);
		
		return userRepository.save(new ApplicationUser(0, username, encodedPassword, authorities));
	}
	
	public LoginResponseDTO loginUser(String username, String password) {
		try {
			Authentication auth = authenticationManager.authenticate(
						new UsernamePasswordAuthenticationToken(username, password)
					);
			
			String token = tokenService.generateJwt(auth);
			
			return new LoginResponseDTO(userRepository.findByUsername(username).get(), token);
		} catch (Exception e) {
			return new LoginResponseDTO(null, "");
		}
	}
	
}
