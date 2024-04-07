package grand.project.users.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import grand.project.users.utils.RSAKeyProperties;

@Configuration
public class SecurityConfiguration {
	
	private final RSAKeyProperties keys;
	
	public SecurityConfiguration(RSAKeyProperties keys) {
		this.keys = keys;
	}

    @Bean
    PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
    
    /**
     * Creates and returns a bean of type AuthenticationManager. This configuration is useful when
     * the user tries to login with user name and password. That time the authenticationManager
     * uses the provided userDetailsService and passwordEncoder to (retrieve the user details from H2 database) and 
     * (encode & verify the password of the user) respectively
     *
     * @param userDetailsService an implementation of the UserDetailsService interface,
     *                           responsible for retrieving user details from a data source
     * @return an AuthenticationManager instance
     */
    @Bean
    AuthenticationManager authManage(UserDetailsService userDetailsService) {
    	// Create a new instance of DaoAuthenticationProvider
    	DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
    	
    	/**
         * Set the UserDetailsService implementation to be used by the DaoAuthenticationProvider.
         * This service is responsible for retrieving user details from a data source, such as a database.
         */
    	daoAuthenticationProvider.setUserDetailsService(userDetailsService);
    	

        /**
         * Set the PasswordEncoder to be used by the DaoAuthenticationProvider for encoding and
         * verifying passwords. The passwordEncoder() method should return a bean of type PasswordEncoder.
         */
    	daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
    	

        /**
         * Create a new instance of ProviderManager, which is an AuthenticationManager implementation
         * that delegates authentication requests to a list of configured AuthenticationProviders.
         * In this case, we pass the configured DaoAuthenticationProvider as the sole provider.
         */
    	return new ProviderManager(daoAuthenticationProvider);
    }
    
    
	
    // this is a SecurityFilterChain bean through which the first request goes through
    // You can create multiple filter chain
    // In case you want multiple SecurityFilterChain beans, you can create them and order them using @Order(...) annotation
	@Bean
	@Order(1)
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			.csrf(csrf -> csrf.disable())
			.authorizeHttpRequests(auth -> {
				auth.requestMatchers("/auth/**").permitAll();
				auth.requestMatchers("/admin/**").hasRole("ADMIN");
				auth.requestMatchers("/user/**").hasAnyRole("ADMIN", "USER");
				auth.anyRequest().authenticated();
				})
			.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))
			.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		return http.build();
	} 
	
	@Bean
	JwtDecoder jwtDecoder() {
		return NimbusJwtDecoder.withPublicKey(keys.getPublicKey()).build();
	}
	
	@Bean
	JwtEncoder jwtEncoder() {
		JWK jwk = new RSAKey.Builder(keys.getPublicKey()).privateKey(keys.getPrivateKey()).build();
		JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
		return new NimbusJwtEncoder(jwks);
	}
	
	/**
	 * The reason we need this method is, in our database we are saving our roles as "USER" and "ADMIN"
	 * But Spring Security requires roles in the form of, "ROLES_USER" and "ROLES_ADMIN"
	 * We don't want to save "ROLES_USER" and "ROLES_ADMIN" in the database
	 */
	@Bean
    JwtAuthenticationConverter jwtAuthenticationConverter(){
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        // This line creates a new instance of JwtGrantedAuthoritiesConverter, which is a converter class 
        // used to extract authorities (roles or permissions) from a JWT token.
        
        jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("roles");
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
        // These lines configure the JwtGrantedAuthoritiesConverter instance:

        // setAuthoritiesClaimName("roles"): This tells the converter to look for a claim named "roles" 
        // in the JWT token, which should contain the user's authorities.
        
        // setAuthorityPrefix("ROLE_"): This sets the prefix to be added to each authority. In this case, 
        // it will prefix each authority with "ROLE_" (e.g., "ROLE_ADMIN", "ROLE_USER").
        // Spring security requires role with the prefix "ROLE_".

        
        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        // These lines create a new instance of JwtAuthenticationConverter and set the previously 
        // configured jwtGrantedAuthoritiesConverter on it. The JwtAuthenticationConverter is 
        // responsible for converting the JWT claims into an Authentication object, which represents 
        // the authenticated user in Spring Security.
        
        return jwtConverter;
    }
}
