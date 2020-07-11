package com.css.authserver.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


/**
 * 由于授权服务器和资源服务器放在一起
 * 需要加个优先级
 */
@Configuration
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Bean
    PasswordEncoder passwordEncoder(){
       return new BCryptPasswordEncoder();
    }

    /**
     * 除了登录接口和认证接口，
     * 其他的任何请求都需要认证
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatchers()
             .antMatchers("/login")
             .antMatchers("/oauth/authorize")
             .and()
             .authorizeRequests().anyRequest().authenticated()
             .and()
             .formLogin()
             .loginPage("/login.html")
             .loginProcessingUrl("/login")
             .permitAll()
             .and()
             .csrf().disable();
    }

    /**
     * 对一些静态资源放行
     * 不经过spring boot 的过滤器直接过
     * @param web
     * @throws Exception
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/login.html", "/css/**", "/js/**", "/images/**");
    }

    /**
     * 提供的用户，内存里
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("javaboy")
                .password(passwordEncoder().encode("123"))
                .roles("admin");
    }
}

