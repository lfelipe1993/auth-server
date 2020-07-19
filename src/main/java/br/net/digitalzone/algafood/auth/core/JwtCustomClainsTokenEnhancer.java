package br.net.digitalzone.algafood.auth.core;

import java.util.HashMap;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

public class JwtCustomClainsTokenEnhancer implements TokenEnhancer {

	@Override
	// Nesse momento o token ainda nao foi assinado (emitido)
	// OAuth2Authentication -> representa a autenticacao realizada na hora que
	// pedimos pra gerar o token.
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {

		if (authentication.getPrincipal() instanceof AuthUser) {
			var authUser = (AuthUser) authentication.getPrincipal();

			var info = new HashMap<String, Object>();
			info.put("nome_completo", authUser.getFullName());
			info.put("usuario_id", authUser.getUserId());

			// OAuth2AccessToken é uma implementação de DefaultOAuth2AccessToken
			var oAuth2AccessToken = (DefaultOAuth2AccessToken) accessToken;
			oAuth2AccessToken.setAdditionalInformation(info);
		}
		// retorno o que recebo
		return accessToken;
	}

}
