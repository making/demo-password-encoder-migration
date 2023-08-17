package com.example;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.Map;

@Configuration
public class SecurityConfig {

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http,
			SecurityContextRepository securityContextRepository) throws Exception {
		http.authorizeHttpRequests(
				authorize -> authorize.requestMatchers("/signup", "/error").permitAll().anyRequest().hasRole("USER"))
			.formLogin(Customizer.withDefaults())
			.securityContext(securityContext -> securityContext.securityContextRepository(securityContextRepository));
		return http.build();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		String idForEncode = "pbkdf2@SpringSecurity_v5_8";
		DelegatingPasswordEncoder passwordEncoder = new DelegatingPasswordEncoder(idForEncode, Map.of(idForEncode,
				Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8(), "bcrypt", new BCryptPasswordEncoder()));
		return passwordEncoder;
	}

	@Bean
	public SecurityContextRepository securityContextRepository() {
		return new DelegatingSecurityContextRepository(new RequestAttributeSecurityContextRepository(),
				new HttpSessionSecurityContextRepository());
	}

}
