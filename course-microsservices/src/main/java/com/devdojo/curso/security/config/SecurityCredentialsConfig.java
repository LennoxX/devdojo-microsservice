package com.devdojo.curso.security.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.devdojo.core.property.JwtConfiguration;
import com.devdojo.token.security.config.SecurityTokenConfig;
import com.devdojo.token.security.converter.TokenConverter;
import com.devdojo.token.security.filter.JwtAuthorizationFilter;

import lombok.RequiredArgsConstructor;

@EnableWebSecurity
public class SecurityCredentialsConfig extends SecurityTokenConfig {

	public SecurityCredentialsConfig(JwtConfiguration jwtConfiguration) {
		super(jwtConfiguration);
		// TODO Auto-generated constructor stub
	}

	private TokenConverter tokenConverter = new TokenConverter();

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.addFilterAfter(new JwtAuthorizationFilter(jwtConfiguration, tokenConverter),
				UsernamePasswordAuthenticationFilter.class);
		super.configure(http);
	}

}
