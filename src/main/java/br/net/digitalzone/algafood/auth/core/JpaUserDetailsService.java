package br.net.digitalzone.algafood.auth.core;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import br.net.digitalzone.algafood.auth.domain.Usuario;
import br.net.digitalzone.algafood.auth.domain.UsuarioRepository;

@Service
//Vai usar essa implementação para consultar o usuário
public class JpaUserDetailsService implements UserDetailsService {

	@Autowired
	private UsuarioRepository usuarioRepository;

	// nao pode abrir e fechar o entityManager, pois na hora de buscar o grupo ele
	// estava fechado
	@Transactional(readOnly = true)
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Usuario usuario = usuarioRepository.findByEmail(username)
				.orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado com e-mail informado"));

		return new AuthUser(usuario, getAuthorities(usuario));
	}

	private Collection<GrantedAuthority> getAuthorities(Usuario usuario) {
		return usuario.getGrupos().stream().flatMap(grupo -> grupo.getPermissoes().stream())
				.map(permissao -> new SimpleGrantedAuthority(permissao.getNome().toUpperCase()))
				.collect(Collectors.toSet());
	}

}
