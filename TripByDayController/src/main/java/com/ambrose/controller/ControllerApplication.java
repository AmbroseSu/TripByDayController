package com.ambrose.controller;

import com.ambrose.repository.entities.User;
import com.ambrose.repository.entities.enums.Role;
import com.ambrose.repository.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
@EnableConfigurationProperties
@ComponentScan(basePackages = {"com.ambrose.service", "com.ambrose.repository" , "com.ambrose.controller"})
public class ControllerApplication implements CommandLineRunner {

	@Autowired
	private UserRepository userRepository;

	public static void main(String[] args) {
		SpringApplication.run(ControllerApplication.class, args);
	}

	public void run(String...args){
		User adminAccount = userRepository.findByRole(Role.ADMIN);
		if(null == adminAccount){
			User user = new User();

			user.setEmail("admin@gmail.com");
			user.setFullname("admin");
			//user.setSecondname("admin");
			user.setRole(Role.ADMIN);
			user.setEnabled(true);
			user.setLogin("admin");
			user.setPassword(new BCryptPasswordEncoder().encode("admin"));
			userRepository.save(user);
		}
	}


}
