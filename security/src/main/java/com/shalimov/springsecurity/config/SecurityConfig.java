package com.shalimov.springsecurity.config;

import com.shalimov.springsecurity.model.Permission;
import com.shalimov.springsecurity.model.Role;
import com.shalimov.springsecurity.security.JwtConfigurer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.bind.annotation.RequestBody;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {



    private final JwtConfigurer jwtConfigurer;

    public SecurityConfig(JwtConfigurer jwtConfigurer) {
        this.jwtConfigurer = jwtConfigurer;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/api/v1/auth/login").permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .apply(jwtConfigurer);
    }
    // На основание ролей
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .csrf().disable()
//                .authorizeRequests()
//                .antMatchers("/").permitAll()
//                .antMatchers(HttpMethod.GET,"api/**").hasAnyRole(Role.ADMIN.name(),Role.USER.name())
//                .antMatchers(HttpMethod.DELETE,"api/**" ).hasRole(Role.ADMIN.name())
//                .antMatchers(HttpMethod.POST,"api/**" ).hasRole(Role.ADMIN.name())
//                .anyRequest()
//                .authenticated()
//                .and()
//                .httpBasic();
//    }
    // На основание ролей/пермишенов и удаление сесии
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .csrf().disable()
//                .authorizeRequests()
//                .antMatchers("/").permitAll()
//                .anyRequest()
//                .authenticated()
//                .and()
//                .formLogin()
//                .loginPage("/auth/login").permitAll()
//                .defaultSuccessUrl("/auth/success")
//                .and()
//                .logout()
//                .logoutRequestMatcher(new AntPathRequestMatcher("/auth/logout","POST"))
//                .invalidateHttpSession(true)
//                .clearAuthentication(true)
//                .deleteCookies("JSESSIONID")
//                .logoutSuccessUrl("/Auth/login");
//    }


    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
// На основание ролей
//    @Bean
//    @Override
//    protected UserDetailsService userDetailsService() {
//        return new InMemoryUserDetailsManager(
//                User.builder()
//                        .username("admin")
//                        .password(passwordEncoder().encode("admin"))
//                        .roles(Role.ADMIN.name())
//                        .build(),
//                User.builder()
//                        .username("user")
//                        .password(passwordEncoder().encode("user"))
//                        .roles(Role.USER.name())
//                        .build()
//        );
//    }

    // На основание ролей/пермишенов
//    @Bean
//    @Override
//    protected UserDetailsService userDetailsService() {
//        return new InMemoryUserDetailsManager(
//                User.builder()
//                        .username("admin")
//                        .password(passwordEncoder().encode("admin"))
//                        .authorities(Role.ADMIN.getAuthorities())
//                        .build(),
//                User.builder()
//                        .username("user")
//                        .password(passwordEncoder().encode("user"))
//                        .authorities(Role.USER.getAuthorities())
//                        .build()
//        );
//    }

    @Bean
    protected PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }





//    private final UserDetailsService userDetailsService;
//    @Autowired
//    public SecurityConfig(@Qualifier("userDetailsServiceImpl") UserDetailsService userDetailsService) {
//        this.userDetailsService = userDetailsService;
//    }
//    @Override
//    protected void configure (AuthenticationManagerBuilder auth) throws Exception{
//        auth.authenticationProvider(daoAuthenticationProvider());
//    }
//    @Bean
//    protected DaoAuthenticationProvider daoAuthenticationProvider() {
//        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
//        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
//        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
//        return daoAuthenticationProvider;
//    }
}
