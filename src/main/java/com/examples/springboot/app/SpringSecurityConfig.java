package com.examples.springboot.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

//import com.examples.springboot.app.auth.filter.JWTAuthenticationFilter;
//import com.examples.springboot.app.auth.filter.JWTAuthorizationFilter;
//import com.examples.springboot.app.auth.service.JWTService;
import com.examples.springboot.app.models.service.JpaUserDetailsService;


@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
@Configuration
public class SpringSecurityConfig {

	@Autowired
	private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private JpaUserDetailsService userDetailsService;
    
   // @Autowired
   // private JWTService jwtService;
    
	@Configuration
	@EnableWebSecurity
	public class SecurityConfig {

		@Bean
		public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			http.authorizeHttpRequests(authorize -> authorize
					.requestMatchers("/", "/css/**","/js/**","/images/**","/listar**","/locale","/api/clientes/**").permitAll()
					.anyRequest().authenticated())
				
					//.exceptionHandling((exceptionHandling) -> exceptionHandling.accessDeniedPage("/error_403"))
					//.formLogin(formLogin -> formLogin.successHandler(successHandler).loginPage("/login")
					//.logout((logout) -> logout.logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler()))
					//.logout((logout) -> logout.logoutUrl("/","/login"))
			
					//		.permitAll())
					//.addFilter(new JWTAuthenticationFilter(authenticationManager(),jwtService))
					//.addFilter(new JWTAuthorizationFilter(authenticationManager(),jwtService))
					.csrf(csrf -> csrf.disable())
					.sessionManagement((session) -> session
				    .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
					.rememberMe(Customizer.withDefaults());
			

			return http.build();
		}
	}

    @Autowired
    public void userDetailsService(AuthenticationManagerBuilder build) throws Exception
	{
		
    	build.userDetailsService(userDetailsService)
		.passwordEncoder(passwordEncoder);
    	
	}
}
