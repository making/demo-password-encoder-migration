package com.example.account;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.DataClassRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AccountUserDetailsService implements UserDetailsService{

	private final JdbcTemplate jdbcTemplate;

	public AccountUserDetailsService(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		try {
			Account account = this.jdbcTemplate.queryForObject(
					"SELECT username, password FROM account WHERE username = ?",
					new DataClassRowMapper<>(Account.class), username);
			return new AccountUserDetails(account);
		}
		catch (EmptyResultDataAccessException e) {
			throw new UsernameNotFoundException("user not found", e);
		}
	}

}
