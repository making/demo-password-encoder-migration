package com.example;

import com.example.account.Account;
import com.example.account.AccountUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class SignupController {

	private final JdbcTemplate jdbcTemplate;

	private final PasswordEncoder passwordEncoder;

	private final SecurityContextRepository securityContextRepository;

	public SignupController(JdbcTemplate jdbcTemplate, PasswordEncoder passwordEncoder,
			SecurityContextRepository securityContextRepository) {
		this.jdbcTemplate = jdbcTemplate;
		this.passwordEncoder = passwordEncoder;
		this.securityContextRepository = securityContextRepository;
	}

	@GetMapping(path = "/signup")
	public String signup() {
		return "signup";
	}

	@PostMapping(path = "/signup")
	public String signup(SignupForm form, HttpServletRequest request, HttpServletResponse response) {
		String encoded = this.passwordEncoder.encode(form.password());
		this.jdbcTemplate.update("INSERT INTO account(username, password) VALUES (?, ?)", form.username(), encoded);

		// automatic login after signup
		AccountUserDetails userDetails = new AccountUserDetails(new Account(form.username(), encoded));
		Authentication token = UsernamePasswordAuthenticationToken.authenticated(userDetails, null,
				userDetails.getAuthorities());
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(token);
		this.securityContextRepository.saveContext(context, request, response);
		return "redirect:/";
	}

	record SignupForm(String username, String password) {
	}

}
