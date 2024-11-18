
package seg3x02.converter

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder

@Configuration
@EnableWebSecurity
class WebSecurityConfig {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeRequests { auth -> auth.anyRequest().authenticated() }
            .httpBasic() // Enable basic authentication
            .and()
            .formLogin().disable() // Disable form-based login
            .csrf().disable() // Disable CSRF for simplicity in API testing
        return http.build()
    }

    @Bean
    fun userDetailsService(): UserDetailsService {
        val user1 = User.withUsername("user1")
            .password(passwordEncoder().encode("pass1"))
            .roles("USER")
            .build()

        val user2 = User.withUsername("user2")
            .password(passwordEncoder().encode("pass2"))
            .roles("USER")
            .build()

        return InMemoryUserDetailsManager(user1, user2)
    }

    @Bean
    fun passwordEncoder() = BCryptPasswordEncoder()
}
