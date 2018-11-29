package com.sakura.springbootsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @Author: Sakura
 * @Description:
 * @Date: 2018/11/28 14:02
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * @Description: 定制授权规则
     * @auther: Sakura
     * @date: 2018/11/28 14:39
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("VIP1")
                .antMatchers("/level2/**").hasRole("VIP2")
                .antMatchers("/level3/**").hasRole("VIP3");
        // 开启提供的登录功能,不能登录会提供一个登录页面
        // /login  登录页面
        // /login?error  登录失败
        http.formLogin();

        // 开启注销功能,默认回到登录页面,清除session
        http.logout().logoutSuccessUrl("/");  // 注销成功后返回的地址

        // 开启记住我功能,向浏览器发送一个cookie,下次登录时发送cookie实现免登陆
        // 点击注销后会清除cookie
        // cookie默认保存15天
        // 使用.rememberMeParameter("rememberMe")设置传递的参数
        http.rememberMe();

        /**
         *  自定义登录页面:
         *  http.formLogin().usernameParameter("userName")
         *                  .passwordParameter("password")
         *                  .loginPage("/userLogin");
         *  默认形式post的"/login"表示登录处理
         *  如果使用了自定义的loginPage,那么loginPage的"/userLogin"的post请求为登录处理
         */
    }

    /**
     * @Description: 定制认证规则
     * @auther: Sakura
     * @date: 2018/11/28 14:53
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 从内存中获取用户信息
        auth.inMemoryAuthentication()
                .passwordEncoder(passwordEncoder())
                .withUser("sakura").password(passwordEncoder().encode("123")).roles("VIP1","VIP2","VIP3")
                .and()
                .withUser("peach").password(passwordEncoder().encode("123")).roles("VIP1");
    }

    // SpringSecurity5.*版本设置密码时需要注入此bean
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
