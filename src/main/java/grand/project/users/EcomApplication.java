package grand.project.users;

import java.util.HashSet;
import java.util.Set;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import grand.project.users.models.ApplicationUser;
import grand.project.users.models.Role;
import grand.project.users.repository.RoleRepository;
import grand.project.users.repository.UserRepository;

@SpringBootApplication
public class EcomApplication {

	public static void main(String[] args) {
		SpringApplication.run(EcomApplication.class, args);
	}
	
	@Bean
	CommandLineRunner run(RoleRepository roleRepository, UserRepository userRepository, PasswordEncoder passwordEncoder) {
		return args -> {
			if(roleRepository.findByAuthority("ADMIN").isPresent()) return;
			Role adminRole	= roleRepository.save(new Role("ADMIN"));
			roleRepository.save(new Role("USER"));
			
			Set<Role> roles = new HashSet<>();
			roles.add(adminRole);
			
			ApplicationUser admin = new ApplicationUser(1, "admin", passwordEncoder.encode("password"), roles);
			
			userRepository.save(admin);
		};
	}
	
	// This is a method annotated with @Bean, which means that it will be executed when the Spring application starts up. 
	// The method takes three dependencies: RoleRepository, UserRepository, and PasswordEncoder.

	// It checks if the "ADMIN" role already exists in the database using roleRepository.findByAuthority("ADMIN").isPresent(). 
	// If it exists, it returns without doing anything else.
	
	// If the "ADMIN" role doesn't exist, it creates a new Role object with the authority "ADMIN" and saves it to 
	// the database using roleRepository.save(new Role("ADMIN")).

	
	// It creates another role with the authority "USER" and saves it to the database using roleRepository.save(new Role("USER")).
	// It creates a Set<Role> called roles and adds the adminRole to it.
	        
	// It saves the new ApplicationUser (admin) to the database using userRepository.save(admin).
	// That means even if the application is totally new, it'll always have at least one user "admin" with password as "password"

	// This method sets up the initial data for the application. It ensures that the "ADMIN" and "USER" roles exist 
	// in the database, and if the "ADMIN" role doesn't exist, it creates an admin user with the username "admin" 
	// and password "password", assigning the "ADMIN" role to this user.

	

}
