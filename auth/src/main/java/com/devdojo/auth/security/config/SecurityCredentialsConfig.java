package com.devdojo.auth.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.devdojo.auth.security.filter.JwtUsernameAndPasswordAuthenticationFilter;
import com.devdojo.core.property.JwtConfiguration;
import com.devdojo.token.security.config.SecurityTokenConfig;
import com.devdojo.token.security.converter.TokenConverter;
import com.devdojo.token.security.creator.TokenCreator;
import com.devdojo.token.security.filter.JwtAuthorizationFilter;

@EnableWebSecurity
public class SecurityCredentialsConfig extends SecurityTokenConfig {

	public SecurityCredentialsConfig(JwtConfiguration jwtConfiguration) {
		super(jwtConfiguration);
		// TODO Auto-generated constructor stub
	}

	@Autowired
	private UserDetailsService userDetailsService;

	private final TokenCreator tokenCreator = new TokenCreator();
	private TokenConverter tokenConverter = new TokenConverter();

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.addFilter(
				new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfiguration, tokenCreator))
				.addFilterAfter(new JwtAuthorizationFilter(jwtConfiguration, tokenConverter),
						UsernamePasswordAuthenticationFilter.class);
		super.configure(http);
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// TODO Auto-generated method stub
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
