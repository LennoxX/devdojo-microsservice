package com.devdojo.token.security.creator;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import com.devdojo.core.model.ApplicationUser;
import com.devdojo.core.property.JwtConfiguration;
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

@Service
public class TokenCreator {

	private JwtConfiguration jwtConfiguration = new JwtConfiguration();

	public SignedJWT createSignedToken(Authentication authentication) {
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
				.claim("userId", applicationUser.getId()).issuer("http://academy.devdojo.com").issueTime(new Date())
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

	public String encryptToken(SignedJWT signedJWT) {
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
