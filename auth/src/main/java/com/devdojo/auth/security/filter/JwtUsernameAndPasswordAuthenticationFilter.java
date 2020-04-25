package com.devdojo.auth.security.filter;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.devdojo.core.model.ApplicationUser;
import com.devdojo.core.property.JwtConfiguration;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
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

	public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager2,
			JwtConfiguration jwtConfiguration2) {
		this.authenticationManager = authenticationManager2;
		this.jwtConfiguration = jwtConfiguration2;
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
		SignedJWT signedJWT = createSignedToken(authResult);
		String encryptedToken = encryptToken(signedJWT);
		response.addHeader("Access-Control-Expose-Headers", "XSRF-TOKEN, " + jwtConfiguration.getHeader().getName());
		response.addHeader(jwtConfiguration.getHeader().getName(),
				jwtConfiguration.getHeader().getPrefix() + encryptedToken);

	}

	private SignedJWT createSignedToken(Authentication authentication) {
		ApplicationUser principal = (ApplicationUser) authentication.getPrincipal();
		JWTClaimsSet jwtClaimsSet = createJwtClaimSet(authentication, principal);

		KeyPair keyPair = generateKeyPair();

		JWK jwk = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic()).keyID(UUID.randomUUID().toString()).build();

		SignedJWT signedJWT = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.RS256).jwk(jwk).type(JOSEObjectType.JWT).build(), jwtClaimsSet);

		RSASSASigner rsassaSigner = new RSASSASigner(keyPair.getPrivate());

		try {
			signedJWT.sign(rsassaSigner);
		} catch (JOSEException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return signedJWT;
	}

	private JWTClaimsSet createJwtClaimSet(Authentication authentication, ApplicationUser applicationUser) {

		return new JWTClaimsSet.Builder().subject(applicationUser.getUsername())
				.claim("authorities",
						authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority)
								.collect(Collectors.toList()))
				.issuer("http://academy.devdojo.com").issueTime(new Date())
				.expirationTime(new Date(System.currentTimeMillis() + (jwtConfiguration.getExpiration() * 1000)))
				.build();
	}

	private KeyPair generateKeyPair() {
		KeyPairGenerator generator = null;
		try {
			generator = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		generator.initialize(2048);

		return generator.genKeyPair();

	}

	private String encryptToken(SignedJWT signedJWT) {
		try {
			DirectEncrypter directEncrypter = new DirectEncrypter(jwtConfiguration.getPrivateKey().getBytes());
			JWEObject jweObject = new JWEObject(
					new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256).contentType("JWT").build(),
					new Payload(signedJWT));
			jweObject.encrypt(directEncrypter);
			return jweObject.serialize();
		} catch (KeyLengthException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JOSEException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;

	}

}
