package ca.uhn.fhir.jpa.starter.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

	@Bean
	@ConditionalOnProperty(name = "auth.enabled", havingValue = "true")
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.headers(header -> header.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
			.authorizeHttpRequests((authorize) -> authorize
				.requestMatchers("/fhir/metadata").permitAll()
				.requestMatchers("/fhir/**").hasRole("USER")
			)
			.csrf(AbstractHttpConfigurer::disable)
			.httpBasic(Customizer.withDefaults())
			.formLogin(AbstractHttpConfigurer::disable);

		return http.build();
	}

	@Bean
	@ConditionalOnProperty(name = "auth.enabled", havingValue = "false", matchIfMissing = true)
	public SecurityFilterChain securityFilterChainUnsecure(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests((authorize) -> authorize
				.anyRequest().permitAll()
			)
			.csrf(AbstractHttpConfigurer::disable)
			.httpBasic(AbstractHttpConfigurer::disable)
			.formLogin(AbstractHttpConfigurer::disable);

		return http.build();
	}

	@Bean
	@ConditionalOnProperty(name = "auth.enabled", havingValue = "true")
	public UserDetailsService userDetailsService(@Value("${auth.username}") String username,
		@Value("${auth.password}") String password) {
		UserDetails userDetails = User.withDefaultPasswordEncoder()
			.username(username)
			.password(password)
			.authorities("ROLE_USER")
			.build();

		return new InMemoryUserDetailsManager(userDetails);
	}
}
