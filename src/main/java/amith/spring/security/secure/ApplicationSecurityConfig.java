package amith.spring.security.secure;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter
{
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
		super();
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception{
		 http
				.authorizeRequests()
				.antMatchers("/","index","/css/*","/js/*")
				.permitAll()
				.anyRequest()
				.authenticated()
				.and()
				.httpBasic();			
	}

	@Override
	@Bean
	protected UserDetailsService userDetailsService() {
		UserDetails amith = User.builder()
				.username("Amith")
				.password(passwordEncoder.encode("1234"))
				.roles("Student")
				.build();
		
		return new InMemoryUserDetailsManager(amith);
	}
	
	
}
