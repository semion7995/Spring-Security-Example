package com.apress.todo.todosimplesecurity.config;

import com.apress.todo.todosimplesecurity.directory.Person;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.hateoas.MediaTypes;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

@EnableConfigurationProperties(ToDoProperties.class)
@Configuration
@Slf4j
public class ToDoSecurityConfig extends WebSecurityConfigurerAdapter {
    private RestTemplate restTemplate;
    private ToDoProperties toDoProperties;
    private UriComponentsBuilder builder;

    public ToDoSecurityConfig (RestTemplateBuilder restTemplateBuilder, ToDoProperties toDoProperties){
        this.toDoProperties = toDoProperties;
        this.restTemplate = restTemplateBuilder.basicAuthentication(toDoProperties.getUsername(), toDoProperties.getPassword()).build();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                try{
                builder = UriComponentsBuilder.fromUriString(toDoProperties.getFindByEmailUri()).queryParam("email", username);
                log.info("Querying: " + builder.toUriString());
                    ResponseEntity<Person> responseEntity = restTemplate.exchange(RequestEntity.get(URI.create(builder.toUriString())).accept(MediaTypes.HAL_JSON).build(),
                            new ParameterizedTypeReference<Person>() {
                            });

                    if (responseEntity.getStatusCode() == HttpStatus.OK){
                        Person person = responseEntity.getBody();

                        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
                        String password = encoder.encode(person.getPassword());
                        return User.withUsername(person.getEmail()).password(password).accountLocked(!person.isEnabled()).roles(person.getRole()).build();
                    }
                } catch (Exception e){
                    e.printStackTrace();
                }
                throw new UsernameNotFoundException(username);
            }
        });
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                .antMatchers("/","/api/**").hasRole("USER")
                .and()
                .formLogin().loginPage("/login").permitAll()
                .and()
                .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/login")
                .and()
                .httpBasic();
    }

    //
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .passwordEncoder(passwordEncoder())
//                .withUser("apress")
//                .password(passwordEncoder().encode("2134"))
//                .roles("ADMIN", "USER")
//                .and().withUser("admin").password(passwordEncoder().encode("2134")).roles("ADMIN", "USER")
//        .and().withUser("scrypt").password(passwordEncoder().encode("2134")).roles("ADMIN", "USER")
//        ;
//    }
//
//    @Bean
//    public BCryptPasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//    @Bean
//    public Pbkdf2PasswordEncoder passwordEncoder2(){
//        return new Pbkdf2PasswordEncoder();
//    }
//    @Bean
//    public SCryptPasswordEncoder passwordEncoder3(){
//        return new SCryptPasswordEncoder();
//    }
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests().requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
//                .anyRequest().fullyAuthenticated()
//                .and()
//                .formLogin().loginPage("/login").permitAll()
//                .and()
//                .logout()
//                .logoutRequestMatcher(
//                        new AntPathRequestMatcher("/logout"))
//                .logoutSuccessUrl("/login")
//        .and().httpBasic(); // добавляем возмодность общения приложения через Rest API програмным образом
//    }


}
