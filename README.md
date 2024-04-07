# spring_boot_auth
User and Admin Authentication + Authorization using Spring Boot 3 + Spring Security v6.2.3

# Running it locally
Make sure you have java 17 and JDK 17 installed

>>

# Classes Description

##### SecurityConfiguration
1. Configuration for protected and unprotected routes based on the pattern
2. Implements JWT Encoder and JWT Decoder for RSA Public Private Key
3. Provides strategy to handle JWT and session
4. Provides password encoder 
5. authManage - to retrieve UserDetails

csrf -> cross site request forgery

### package .models

##### ApplicationUser Implements UserDetails (spring security interface)
1. Columns - userId, username, password, authorities
2. Authorities is a set of Roles (implements GrantedAuthority) with many to many relation
3. It's a junction table with many to many relationships where the (joining column) owning side is the ApplicationUser and the inverse join column (non-owning side) is the Role.

##### Role Implements GrantedAuthority 
1. Columns - roleId, authority

##### LoginResponseDTO
1. Fields - user (type AuthenticationUser), jwt (string)

##### RegistrationDTO
1. Fields - username, password (both string)

### package .repository

##### RoleRepository extends JpaRepository
1. Method findByAuthority

##### UserRepository extends JpaRepository
1. Method findByUsername

### package .services

##### UserService.java
1. A class to implement UserDetailsService

##### 