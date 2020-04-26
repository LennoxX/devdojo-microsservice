package com.devdojo.token.security.config;

import javax.servlet.http.HttpServletResponse;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.cors.CorsConfiguration;

import com.devdojo.core.property.JwtConfiguration;

public class SecurityTokenConfig extends WebSecurityConfigurerAdapter {

	protected final JwtConfiguration jwtConfiguration;

	public SecurityTokenConfig(JwtConfiguration jwtConfiguration) {
		this.jwtConfiguration = jwtConfiguration;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues())
				.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
				.exceptionHandling()
				.authenticationEntryPoint((req, resp, e) -> resp.sendError(HttpServletResponse.SC_UNAUTHORIZED)).and()
				.authorizeRequests().antMatchers(jwtConfiguration.getLoginUrl()).permitAll()
				.antMatchers("/course/admin/**").hasRole("ADMIN").anyRequest().authenticated();
	}
}
