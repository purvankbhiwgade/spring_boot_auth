package grand.project.users.services;

import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

	private JwtEncoder jwtEncoder;
		
	public TokenService(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder) {
		super();
		this.jwtEncoder = jwtEncoder;
	}
	
	public String generateJwt(Authentication auth) {
		
		Instant now = Instant.now();
		
		String scope = auth.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.joining(" "));
		
		// This line retrieves the authorities (roles or permissions) associated with the 
		// Authentication object (user).  
		// It converts the Collection<GrantedAuthority> (user's role) to a string, 
		// where each authority is separated by a space. This string represents the scope or roles claim in the JWT.

		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuer("self")
				.issuedAt(now)
				.subject(auth.getName())
				.claim("roles", scope)
				.build();
		
		// Here, it creates a JwtClaimsSet object, which represents the claims or payload of the JWT. 
		// The claims are set using the following methods:
		//
		//		    issuer("self"): Sets the issuer claim, indicating that the JWT is self-issued.
		//		    issuedAt(now): Sets the issued-at claim with the current timestamp.
		//		    subject(auth.getName()): Sets the subject claim with the name of the authenticated user. This is the user whom we're sending the JWT to
		//		    claim("roles", scope): Adds a custom claim named "roles" with the value of the scope string, which contains the user's roles or authorities.

		
		
		return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
	}
}
