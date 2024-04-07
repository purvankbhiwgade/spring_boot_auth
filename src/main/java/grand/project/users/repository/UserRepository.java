package grand.project.users.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import grand.project.users.models.ApplicationUser;

@Repository
public interface UserRepository extends JpaRepository<ApplicationUser, Integer> {
	Optional<ApplicationUser> findByUsername(String username);
}


// @Repository is a Spring annotation that marks this interface as a repository 
// component, allowing Spring to automatically create an instance of this interface 
// during runtime. 

// UserRepository 
// is an interface that extends JpaRepository<ApplicationUser, Integer>. 
// This means that UserRepository inherits all the common database operations provided by 
// JpaRepository for the ApplicationUser entity, where Integer represents the type of the 
// primary key (user_id in this case).

// Optional<ApplicationUser> findByUsername(String username)
// is a custom method declaration that defines a query to find an ApplicationUser entity by its username field. 

// findByUsername()
// Spring Data JPA automatically implements this method based on the naming convention 
// (the method name starts with findBy followed by the field name).
