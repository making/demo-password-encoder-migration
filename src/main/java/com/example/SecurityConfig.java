package com.example;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Objects;

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
		PasswordEncoder legacyMd5Encoder = new PasswordEncoder() {
			@Override
			public String encode(CharSequence rawPassword) {
				try {
					MessageDigest messageDigest = MessageDigest.getInstance("MD5");
					return new String(Hex.encode(messageDigest.digest(Utf8.encode(rawPassword))));
				}
				catch (NoSuchAlgorithmException e) {
					throw new RuntimeException(e);
				}
			}

			@Override
			public boolean matches(CharSequence rawPassword, String encodedPassword) {
				return Objects.equals(this.encode(rawPassword), encodedPassword);
			}
		};
		String idForEncode = "pbkdf2@SpringSecurity_v5_8";
		DelegatingPasswordEncoder passwordEncoder = new DelegatingPasswordEncoder(idForEncode, //
				Map.of(idForEncode, Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8()));
		passwordEncoder.setDefaultPasswordEncoderForMatches(legacyMd5Encoder);
		return passwordEncoder;
	}

	@Bean
	public SecurityContextRepository securityContextRepository() {
		return new DelegatingSecurityContextRepository(new RequestAttributeSecurityContextRepository(),
				new HttpSessionSecurityContextRepository());
	}

}
