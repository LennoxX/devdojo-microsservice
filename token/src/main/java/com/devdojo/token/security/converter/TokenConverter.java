package com.devdojo.token.security.converter;

import java.nio.file.AccessDeniedException;
import java.text.ParseException;

import org.springframework.stereotype.Service;

import com.devdojo.core.property.JwtConfiguration;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

@Service
public class TokenConverter {

	private JwtConfiguration jwtConfiguration = new JwtConfiguration();

	public String decryptToken(String encryptedToken) {
		JWEObject jweObject;
		try {
			jweObject = JWEObject.parse(encryptedToken);
			DirectDecrypter decrypter = new DirectDecrypter(jwtConfiguration.getPrivateKey().getBytes());
			jweObject.decrypt(decrypter);
			return jweObject.getPayload().toSignedJWT().serialize();
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyLengthException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JOSEException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public void validateTokenSignature(String singedToken) {
		SignedJWT signedJWT;
		try {
			signedJWT = SignedJWT.parse(singedToken);
			RSAKey publicKey = RSAKey.parse(signedJWT.getHeader().getJWK().toJSONObject());

			if (!signedJWT.verify(new RSASSAVerifier(publicKey))) {
				throw new AccessDeniedException("Invalid Token Signature!");
			}

		} catch (ParseException e) {
			e.printStackTrace();
		} catch (AccessDeniedException e) {
			e.printStackTrace();
		} catch (JOSEException e) {
			e.printStackTrace();
		}

	}
}
