package com.devdojo.auth.security.filter;

import java.io.IOException;
import java.util.Collections;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.devdojo.core.model.ApplicationUser;
import com.devdojo.core.property.JwtConfiguration;
import com.devdojo.token.security.creator.TokenCreator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtConfiguration jwtConfiguration;

	private final TokenCreator tokenCreator;

	public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager,
			JwtConfiguration jwtConfiguration, TokenCreator tokenCreator) {
		this.authenticationManager = authenticationManager;
		this.jwtConfiguration = jwtConfiguration;
		this.tokenCreator = tokenCreator;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
		UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = null;

		ApplicationUser applicationUser;

		try {
			applicationUser = new ApplicationUser(
					new ObjectMapper().readValue(request.getInputStream(), ApplicationUser.class));

			usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(applicationUser.getUsername(),
					applicationUser.getPassword(), Collections.emptyList());
			usernamePasswordAuthenticationToken.setDetails(applicationUser);
			return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
		} catch (IOException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
		return null;

	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		SignedJWT signedJWT = tokenCreator.createSignedToken(authResult);
		String encryptedToken = tokenCreator.encryptToken(signedJWT);
		response.addHeader("Access-Control-Expose-Headers", "XSRF-TOKEN, " + jwtConfiguration.getHeader().getName());
		response.addHeader(jwtConfiguration.getHeader().getName(),
				jwtConfiguration.getHeader().getPrefix() + encryptedToken);

	}

}
